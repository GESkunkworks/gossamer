#!/bin/bash
#
# chkconfig: 35 95 05
# description: gossamer daemon 

# Run at startup: sudo chkconfig gossamer on

# Load functions from library
. /etc/init.d/functions

# Name of the application
app="gossamer"

# Start the service
run() {
  echo -n $"Starting $app:"
  cd /tmp
  ./$app > /var/log/$app.log 2> /var/log/$app.err < /dev/null &
  
  sleep 1
  
  status $app > /dev/null
  # If application is running
  if [[ $? -eq 0 ]]; then
    # Store PID in lock file
    echo $! > /var/lock/subsys/$app
    success
    echo
  else
    failure
    echo
  fi
}

# Start the service
start() {
  status $app > /dev/null
  # If application is running
  if [[ $? -eq 0 ]]; then
    status $app
  else
    run
  fi
}

# Restart the service
stop() {
  echo -n "Stopping $app: "
  killproc $app
  rm -f /var/lock/subsys/$app
  echo
}

# Reload the service
reload() {
  status $app > /dev/null
  # If application is running
  if [[ $? -eq 0 ]]; then
    echo -n $"Reloading $app:"
    kill -HUP `pidof $app`
    sleep 1
    status $app > /dev/null
    # If application is running
    if [[ $? -eq 0 ]]; then
      success
      echo
    else
      failure
      echo
    fi
  else
    run
  fi
}

# Main logic
case "$1" in
  start)
    start
    ;;
  stop)
    stop
    ;;
  status)
    status $app
    ;;
  restart)
    stop
    sleep 1
    start
    ;;
  reload)
    reload
    ;;
  *)
    echo $"Usage: $0 {start|stop|restart|reload|status}"
    exit 1
esac
exit 0