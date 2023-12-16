echo "🌐 Add host names to /etc/hosts"
if [[ "$OSTYPE" == "darwin"* ]]; then
  sudo sed -i '' '/### --- Homelab START --- ###/,/### --- Homelab END --- ###/d' /etc/hosts
  cat ./hosts >>/etc/hosts
else
  echo "This script is only supported on macOS at the moment... Feel free to contribute support for your OS!"
fi
