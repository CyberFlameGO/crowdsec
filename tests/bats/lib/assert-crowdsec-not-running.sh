if pgrep crowdsec >/dev/null; then
       echo "A CrowdSec process is already running. Please terminate it and run tests again." >&3
       exit 1
fi
