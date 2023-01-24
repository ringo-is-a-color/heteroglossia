#!/bin/bash

set -e
trap "exit" INT

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
  os="linux"
else
  echo "Unsupported OS"
  exit 1
fi
arch=$(uname -m)
if [[ "$arch" == "x86_64" ]]; then
  arch="amd64"
elif [[ "$arch" == "aarch64" ]]; then
  arch="arm64"
else
  echo "Unsupported CPU architecture $arch"
  exit 1
fi

mkdir -p hg
cd hg

version=$(curl -sL https://api.github.com/repos/ringo-is-a-color/heteroglossia/releases/latest | grep '"tag_name":' | cut -d'"' -f4)
echo "Downloading the latest release version ($version) of heteroglossia..."
curl -OL# "https://github.com/ringo-is-a-color/heteroglossia/releases/download/$version/heteroglossia_${version:1}_${os}_${arch}.tar.gz"
printf "Downloading the heteroglossia release's sha256sum...\n"
curl -OL# "https://github.com/ringo-is-a-color/heteroglossia/releases/download/$version/sha256sums.txt"
sha256sum --ignore-missing -c sha256sums.txt
rm sha256sums.txt
tar -xzf heteroglossia_0.1.0_linux_amd64.tar.gz
rm "heteroglossia_${version:1}_${os}_${arch}.tar.gz" LICENSE
mv heteroglossia hg

read -r -p "Do you want to download the rules' file? [y/N] " yN
yN=${yN,,}
if [[ "$yN" =~ ^(y|yes)$ ]]; then
  mkdir -p data
  echo "Downloading the domain and IP set rules' file 'domain-ip-set-rules.db'..."
  curl -OL# "https://github.com/ringo-is-a-color/domain-ip-set-rules/raw/release/domain-ip-set-rules.db"
  echo "Downloading the domain and IP set rules' sha256sum..."
  curl -OL# "https://github.com/ringo-is-a-color/domain-ip-set-rules/raw/release/domain-ip-set-rules.db.sha256sum"
  sha256sum -c domain-ip-set-rules.db.sha256sum
  rm domain-ip-set-rules.db.sha256sum
fi

read -r -p "Do you want to generate client & server's example configuration files? [y/N] " yN
yN=${yN,,}
if [[ "$yN" =~ ^(y|yes)$ ]]; then
  read -r -p "Please enter your server's domain: " domain
  password=$(openssl rand -hex 16)
  echo "An example of client & server config files are generated."
  echo "client.conf.json"
  tee client.conf.json <<END
{
  "inbounds" : {
    "http-socks" : {
      "host" : "::1",
      "port" : 1080
    }
  },
  "outbounds" : {
    "node1" : {
      "host" : "$domain",
      "password" : "$password"
    }
  }
}
END

  echo "server.conf.json"
  tee server.conf.json <<END
{
  "inbounds" : {
    "hg" : {
      "host" : "$domain",
      "password" : "$password",
      "tls-bad-auth-fallback-site-dir" : "site"
    }
  }
}
END
fi

if [[ ! -d /run/systemd/system ]]; then
  exit
fi

read -r -p "Do you want to install client & server's systemd files into /etc/systemd/system/? [y/N] " yN
yN=${yN,,}
if [[ "$yN" =~ ^(y|yes)$ ]]; then
  echo "hg-client.service"
  tee hg-client.service <<END
[Unit]
Description=Heteroglossia Client
Wants=network-online.target
After=network.target network-online.target

[Service]
User=$(whoami)
ExecStart="$PWD/hg" "$PWD/client.conf.json"

[Install]
WantedBy=multi-user.target
END

  echo "hg-server.service"
  tee hg-server.service <<END
[Unit]
Description=Heteroglossia Server
Wants=network-online.target
After=network.target network-online.target

[Service]
User=$(whoami)
AmbientCapabilities=CAP_NET_BIND_SERVICE
ExecStart="$PWD/hg" "$PWD/server.conf.json"

[Install]
WantedBy=multi-user.target
END

  echo "Copying client.conf.json & hg-server.service into /etc/systemd/system/..."
  sudo mv {hg-client,hg-server}.service /etc/systemd/system/
  cat <<END >./remove-systemd-services.sh
#!/bin/bash

echo "Removing client.conf.json & hg-server.service from /etc/systemd/system/..."
sudo rm /etc/systemd/system/{hg-client,hg-server}.service
END
  chmod +x ./remove-systemd-services.sh
fi
