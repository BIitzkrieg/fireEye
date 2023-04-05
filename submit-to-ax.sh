#!/bin/sh
#Directory to monitor
MONITORDIR="/opt/files/"
# get auth token from AX
curl -qgsSkH --no-progress-bar --header "Authorization: Basic [b64 password here]" -D /opt/auth.txt -F form=foo https://hostname/wsapis/v2.0.0/auth/login
# grep token out of returned auth file
token=$(egrep -oh "[a-zA-Z0-9\/=]{48}" auth.txt)
#echo "token is: $token"
inotifywait -m -r --exclude '/\..+' -e create "${MONITORDIR}" |
    while read -r path action file; do
        #echo "The file '$file' appeared in directory '$path' via '$action'"
        fullpath=$path$file
        #echo "the full path is ${fullpath}"
        echo "sending file: "$fullpath""
        curl -qgsSkH 'Content-Type: multipart/form-data' --header "X-FeApi-Token: $token" -F "filename=@${fullpath}" -F 'options={"application":"0", "timeout":"240", "priority":"1", "profiles":["win10x64"], "analysistype":"2","force":"false","prefetch":"1"}' https://hostname/wsapis/v2.0.0/submissions/file
    done
