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

function runCommandWithRootCheck() {
  if [[ $EUID == 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

function download_file_with_progress_bar() {
  if [[ -x "$(command -v wget)" ]]; then
    wget -qN --show-progress "$1"
  else
    curl -fzOL# "$1"
  fi
}

mkdir -p hg
cd hg

if [[ -x "$(command -v wget)" ]]; then
  version=$(wget -qO- https://api.github.com/repos/ringo-is-a-color/heteroglossia/releases/latest | grep '"tag_name":' | cut -d'"' -f4)
else
  version=$(curl -fsL https://api.github.com/repos/ringo-is-a-color/heteroglossia/releases/latest | grep '"tag_name":' | cut -d'"' -f4)
fi

echo "Downloading the latest release version ${version:1} of heteroglossia(hg)..."
download_file_with_progress_bar "https://github.com/ringo-is-a-color/heteroglossia/releases/download/$version/heteroglossia_${version:1}_${os}_${arch}.tar.gz"
echo "Downloading the heteroglossia(hg) release's sha256sum..."
download_file_with_progress_bar "https://github.com/ringo-is-a-color/heteroglossia/releases/download/$version/sha256sums.txt"
sha256sum --ignore-missing -c sha256sums.txt
rm sha256sums.txt
tar -xzf heteroglossia_0.1.0_linux_amd64.tar.gz
rm "heteroglossia_${version:1}_${os}_${arch}.tar.gz"
mv heteroglossia hg

read -r -p "Do you want to download the rules' file? [y/N] " yN
yN=${yN,,}
if [[ "$yN" =~ ^(y|yes)$ ]]; then
  echo "Downloading the domain and IP set rules' file 'domain-ip-set-rules.db'..."
  download_file_with_progress_bar "https://github.com/ringo-is-a-color/domain-ip-set-rules/raw/release/domain-ip-set-rules.db"
  echo "Downloading the domain and IP set rules' sha256sum..."
  download_file_with_progress_bar "https://github.com/ringo-is-a-color/domain-ip-set-rules/raw/release/domain-ip-set-rules.db.sha256sum"
  sha256sum -c domain-ip-set-rules.db.sha256sum
  rm domain-ip-set-rules.db.sha256sum
fi

read -r -p "Do you want to generate client & server's example configuration files? [y/N] " yN
yN=${yN,,}
if [[ "$yN" =~ ^(y|yes)$ ]]; then
  read -r -p "Please enter your server's domain [example.com]: " domain
  domain=${domain:-example.com}
  password=$(openssl rand -hex 16)
  echo "An example of client & server config files are generated."
  echo "'$PWD/client.conf.json'"
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
  echo
  echo "'$PWD/server.conf.json'"
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
  echo
fi

if [[ ! -d /run/systemd/system ]]; then
  exit
fi

read -r -p "Do you want to install client & server's systemd files into '/etc/systemd/system/'? [y/N] " yN
yN=${yN,,}
if [[ "$yN" =~ ^(y|yes)$ ]]; then
  server_systemd_file_content="[Unit]
Description=Heteroglossia(hg) Server
Wants=network-online.target
After=network.target network-online.target

[Service]
User=$(whoami)
AmbientCapabilities=CAP_NET_BIND_SERVICE
ExecStart=\"$PWD/hg\" \"$PWD/server.conf.json\"

[Install]
WantedBy=multi-user.target"
  echo "'/etc/systemd/system/hg-server.service'"
  echo "$server_systemd_file_content"
  runCommandWithRootCheck sh -c "echo '$server_systemd_file_content' > /etc/systemd/system/hg-server.service"
  echo

  client_systemd_file_content="[Unit]
Description=Heteroglossia(hg) Client
Wants=network-online.target
After=network.target network-online.target

[Service]
User=$(whoami)
ExecStart=\"$PWD/hg\" \"$PWD/client.conf.json\"

[Install]
WantedBy=multi-user.target"
  echo "'/etc/systemd/system/hg-client.service'"
  echo "$client_systemd_file_content"
  runCommandWithRootCheck sh -c "echo '$client_systemd_file_content' > /etc/systemd/system/hg-client.service"

  cat <<END >./remove-client-server-systemd-services.sh
#!/bin/bash

echo "Removing hg-server.service & hg-client.service from '/etc/systemd/system/'..."
runCommandWithRootCheck rm /etc/systemd/system/{hg-client,hg-server}.service
echo "Success!"
END
  chmod +x ./remove-client-server-systemd-services.sh
  echo
fi

echo "Success!"
