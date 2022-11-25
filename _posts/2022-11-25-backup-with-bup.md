---
layout: post
description: Backups with Bup
comments: true
date: 2022-11-26
last-update: 2022-11-26
---

Time Machine never really worked for me. Network backups were slow and unreliable, and to make matters worse, my Apple TimeCapsule broke when I needed it the most, causing me to lose many photos and other documents.
Moreover, at some point I needed to do backups for multiple computer, Mac and Linux, so I started to look for an alternative solution.

I found [Bup](https://github.com/bup/bup), slightly more than 2 years ago.
Since then, I have been happy with it, to the point I would like to share my experience and the setup I am using.

## Table of Contents

- [Backups with Bup](#backups-with-bup)
  - [Installing Bup](#installing-bup)
  - [Setting up network storage and Bup server](#setting-up-network-storage-and-bup-server)
    - [Dockerfile](#dockerfile)
    - [Running the container](#running-the-container)
  - [Clients setup](#clients-setup)
    - [First backup](#first-backup)
    - [Restoring data](#restoring-data)
    - [Making recurring backups](#making-recurring-backups)
      - [macOS backup script](#macos-backup-script)
  - [Cleaning up](#cleaning-up)
  - [Off-site data synchronization (disaster recovery)](#off-site-data-synchronization-disaster-recovery)

# Backups with Bup

Bup is a
> "Very efficient backup system based on the git packfile format, providing fast incremental saves and global deduplication (among and within files, including virtual machine images)."

Besides being open source and free to use, Bup has several advantages over other backup systems. The strongest points of Bup are listed in [its documentation](https://github.com/bup/bup/blob/master/README.md#reasons-bup-is-awesome), but I will mention a few here:

- It is _fast_, even for network backups.
- Can efficiently back up _huge_ virtual machine (VM) disk images, databases, and XML files incrementally, even though they're typically all in one huge file, and not use tons of disk space for multiple versions.
- It uses the packfile format from git, so you can access the stored data even if you don't like Bup's user interface.
- Data is shared and _deduplicated_ between incremental backups, even if the backups are made from different computers.
- It works on Linux, FreeBSD, NetBSD, OS X >= 10.4, Solaris, and Windows (with Cygwin, and WSL).

All that being said, chances are that you have never heard of Bup. And the reason is that it is very far from being a polished product, ready for prime time.
Setting it up requires some knowledge and effort. Moreover, since it's not as tested as other solutions, data loss is always possible (although personally, I find it quite reliable).

If at this point you are not scared, you should keep reading.

In the following paragraphs, I will try to provide some guidance by explaining my setup.
Note that my goal is not to give a detailed guide on Bup usage, but rather I would like to give some pointers and ideas to effectively use Bup for your home computers or your small-size company.

## Installing Bup

If you are on Mac, you can install Bup via Homebrew:

```sh
brew install bup
```

Alternatively, Bup community provides [binary packages](https://github.com/bup/bup#from-binary-packages) for the most popular Linux distributions.

Finally, for Windows or for other Unix-flavoured systems, Bup can be installed from source, as described in the [documentation](https://github.com/bup/bup#from-source).

## Setting up network storage and Bup server

Bup can be used to do "local" backups to the computer, for instance to an external drive. Nevertheless, when multiple computers are involved, or simply when you want to do network backups, you need to use Bup as an agent on your computers and set up a server instance on your network.

The server instance can be hosted on the Internet, but, unless you know what you are doing, this is not recommended for speed and security reasons (Bup server doesn't offer encryption and authentication out of the box).

The Bup server needs to have access to a storage large enough to back all your computers up. The exact amount of storage needed depends on many factors, for instance: the number of computers, the size of the live data on those systems, desired frequency and retention of backups.

My advice is to start with abundant storage (e.g., 2x the total disk size of the computers involved) and leave room for expanding it later (e.g., use thin volumes and have few spare bays to add disks).
You may also want to use some form of [RAID](https://en.wikipedia.org/wiki/RAID). This, again, depends on the reliability you want to achieve. I recommend at least a RAID 5, but if you have enough disks you can use RAID 1+0 ([not 0+1!](https://en.wikipedia.org/wiki/RAID#Nested_.28hybrid.29_RAID)).

My personal setup consists of a  NAS also running a Docker container with Bup server. The Docker container mounts a directory local to the NAS and exposes Bup server to my home LAN on port `tcp/1982`.

### Dockerfile

I use this Dockerfile

```Docker
# Bup - Docker image v0.32r3
FROM debian:stable-20220527-slim

env DEBIAN_FRONTEND noninteractive
env DEBCONF_NONINTERACTIVE_SEEN true

RUN apt update && apt upgrade --yes

RUN apt install --yes --no-install-recommends \
  bup \
  htop \
  iproute2 \
  procps \
  python3-fuse \
  python3-tornado \
  tmux

RUN apt clean autoclean \
  ; apt autoremove --yes \
  ; rm -rf /var/lib/{apt,dpkg,cache,log}/

RUN echo "export GIT_DIR=/bup" >> /root/.bashrc
RUN echo "export BUP_DIR=/bup" >> /root/.bashrc

EXPOSE 1982/tcp
ENTRYPOINT [ "/usr/bin/bup", "-d", "/bup", "daemon" ]
```

Which can be built with

```sh
docker build -t dguerri/bup:v0.32r3 .
```

As you probably noticed, I installed few extra packages (like `tmux` and `htop`). You can remove them, but they could be useful for debugging and for cleaning up your backups manually.

### Running the container

The Docker container can be run as shown below. Replace `/share/Bup/backups` with the directory on the Docker server where you want your backups to be stored.

```sh
docker run -d \
  -it \
  --name bup \
  --mount type=bind,source="/share/Bup/backups",target=/bup \
  -p 1982:1982 \
  dguerri/bup:v0.32r3
```

This command will start the docker container with Bup, exposing port 1982 and mounting `/share/Bup/backups` on the host computer to `/bup` in the container.

Needless to say, as long as `/share/Bup/backups` is preserved, the Docker container can be stopped, rebuilt, and restarted, without affecting existing backups.

## Clients setup

**Note**: all the following command are executed as root and are valid for Linux and macOS (and possibly *BSD).

### First backup

First, you need to initialize your local Bup directory.
If you are going to do network backups, this directory will only be used to store the index for your files, so you only need few free Gigabytes.

```sh
/opt/bup/bin/bup -d "/opt/bup/${HOST}-backup" init -r "bup://${NAS_ADDRESS}"
```

The `-d` flag specifies the local directory to be initialized, and `-r` will inform Bup that we will be doing network backups.

You will have to use a valid `NAS_ADDRESS` and, of course, you can change the destination directory.

The second step is to index the files that will be backed up. For instance, to index the content of home directories and `/etc` run the following:

```sh
/opt/bup/bin/bup -d "/opt/bup/${HOST}-backup" index /home/ /etc/

Indexing: 931, done (6673 paths/s).
```

Finally, perform the backup:

```sh
/opt/bup/bin/bup -d "/opt/bup/${HOST}-backup" save -r "bup://${NAS_ADDRESS}" \
  -n "${HOST}-backup" /home/ /etc/

Reading index: 931, done.
Saving: 100.00% (37162/37162k, 931/931 files), done.
Receiving index from server: 5601072/5601072, done.
Receiving index from server: 4661896/4661896, done.
Receiving index from server: 4990756/4990756, done.
Receiving index from server: 5601072/5601072, done.
Receiving index from server: 5601072/5601072, done.
Receiving index from server: 5229512/5229512, done.
Receiving index from server: 110776/110776, done.
```

With `-n "${HOST}-backup"` we specify the name of the backup that will be used on the remote server. This is useful in case we are backing up multiple systems, and it will be the "git branch" we will be able to use to explore the backups on the Bup server.

Depending on the number of files and the amount of data, the first backup can take a long time to complete. Fortunately, the following backups will be incremental and will take only a few minutes.

### Restoring data

Having backups and not being able to restore them is the same as having no backups.
So, you should periodically review your backup, maybe with some automated tests on expected content of some critical file.

For this post, let's see how we can explore our backups and restore files from them.

To list the backups for the current host:

```sh
bup -d "/opt/bup/${HOST}-backup" ls -r "bup://${NAS_ADDRESS}" "${HOST}-backup"
2022-11-26-123217  2022-11-26-123511  latest
```

To restore a given snapshot, simply run:

```sh
bup -d "/opt/bup/${HOST}-backup" restore -r "bup://${NAS_ADDRESS}" \
  "${HOST}-backup/2022-11-26-123217"
Restoring: 933, done
```

The command above will restore data from snapshot `2022-11-26-123217` in the current directory.

You can also cherry-pick specific files, using the following commands.
To list the files in a specific directory in the selected snapshot:

```sh
bup -d "/opt/bup/${HOST}-backup" ls -r  "bup://${NAS_ADDRESS}" \
  "${HOST}-backup/2022-11-26-123217/home/davide/Videos/"
rickroll.mp4 afroninja.mp4
```

To restore a file:

```sh
bup -d "/opt/bup/${HOST}-backup" restore -r "bup://${NAS_ADDRESS}" \
  "${HOST}-backup/2022-11-26-123217/home/davide/Videos/rickroll.mp4"
Restoring: 1, done.
```

### Making recurring backups

Following the first backup, we only need to re-index the files and save the differences to the Bup server.
This, effectively, can be done with the following commands:

```sh
/opt/bup/bin/bup -d "/opt/bup/${HOST}-backup" index /home/ /etc/

/opt/bup/bin/bup -d "/opt/bup/${HOST}-backup" save -r "bup://${NAS_ADDRESS}" \
  -n "${HOST}-backup" /home/ /etc/
```

To execute recurring backups, some sort of cron job must be created.

On Linux, you can use `crond` or a `systemd` timer. While on Mac, the most efficient way is probably using `launchd`.

I, personally, use a shell script to orchestrate my backups. The script invokes Bup two times: the first time for indexing the files to be backed up, and the second time to perform an incremental backup straight to the Bup server.

The caveat with `launchd` is that you cannot give `Full Disk Access` to a shell script.
There are a few ways to work around this, one is giving full-disk access to the shell interpreter. I recommend against doing so, and instead either build a small binary shelling out to your script, and give Full-Disk Access to it, or use [LaunchControl](https://www.soma-zone.com/LaunchControl/), which uses the same "trick" providing a helper named `fdautil`.

**Warning**: giving direct or _indirect_ privileges to shell scripts is, in general, a bad idea: anyone with write access to the script can execute anything with the script privileges. Make sure no user, but root, can edit the script.

#### macOS backup script

Just as an example, here is the script I am using on my MacBooks.
Since backups can be quite demanding in terms of power usage, the script only uploads incremental backups to the server when the laptop is connected to power.

```sh
#!/bin/sh
# MacOS script to do a single network backup via Bup

set -uxe

# Things you need to change
BACKUP_NAME="<your computer name>-backup"
HOMEDIR="/Users/<your username>"
NAS_ADDRESS="<your NAS address>"
# Less likely you need to change these
BUP_EXEC=/opt/homebrew/bin/bup
BACKUP_DIR="/opt/bup/${BACKUP_NAME}"
NAS_PORT="1982"
PIDFILE="/var/run/bup-recurring.sh.pid"


check_battery() {
  if pmset -g ps | head -1 | grep -v "AC Power"; then
    echo "$(date)] Laptop is using battery, exiting"
    exit 0
  else
    true
  fi
}

check_battery

if [ -f "${PIDFILE}" ]; then
  if kill -0 "$(cat "${PIDFILE}")"; then
    echo "[$(date)] Backup already running, exiting"
    exit 1
  else
    echo "[$(date)] Stale pid file detected"
  fi
fi
echo $$ > "${PIDFILE}"
trap 'echo "[$(date)] Removing pidfile"; rm -f -- "${PIDFILE}"' EXIT

# Timeout logic
timeout=3600
to_interval=60
(
    while [ "${timeout}" -gt 0 ]; do
        sleep "${to_interval}"
        kill -0 $$ || exit 0
        timeout="$(( timeout - to_interval))"
        echo "[$(date)] Still alive (timeout in ${timeout} seconds)"
    done

    # Be nice, post SIGTERM first.
    echo "[$(date)] Timeout, sending SIGTERM"
    kill -s TERM $$ && kill -0 $$ || exit 0
    sleep 5
    echo "[$(date)] Sending SIGKILL"
    kill -s KILL $$
) &


# Backup logic
DIRS="${HOMEDIR} /Library /Applications"

check_battery
echo "[$(date)] Starting backup: indexing files"
${BUP_EXEC} -d "${BACKUP_DIR}" index \
  --exclude-rx Library/Caches \
  --exclude-rx Library/Safari/LocalStorage \
  --exclude-rx Library/Application\ Support/Steam \
  --exclude-rx Library/Application\ Support/Dash \
  --exclude-rx Library/Application\ Support/minecraft \
  --exclude-rx Metadata/CoreSpotlight \
  ${DIRS:+ $DIRS}

if /usr/bin/nc -z "${NAS_ADDRESS}" "${NAS_PORT}"; then
  echo "[$(date)] Saving backup to Bup server"
  check_battery
  ${BUP_EXEC} -d "${BACKUP_DIR}" save \
    -r "bup://${NAS_ADDRESS}" -n "${BACKUP_NAME}" ${DIRS:+ $DIRS}
else
 echo "[$(date)] NAS unreachable"
 exit 1
fi
```

Finally, this is the `launchd` configuration I am using to start the above script multiple times every day.
This configuration also specifies that the job:

- Will run as a LowPriorityBackgroundIO process (i.e., the kernel should consider this daemon to be low priority when doing file system I/O when the process is throttled with Darwin-background classification);
- will have a `nice` level of 11 (lower priority than default);
- will redirect `stdout` and `stderr` respectively to `/tmp/local.bup.job.stdout` and `/tmp/local.bup.job.stderr`.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
 <key>KeepAlive</key>
 <false/>
 <key>Label</key>
 <string>local.bup.job</string>
 <key>LowPriorityBackgroundIO</key>
 <true/>
 <key>LowPriorityIO</key>
 <true/>
 <key>Nice</key>
 <integer>11</integer>
 <key>ProgramArguments</key>
 <array>
  <string>/usr/local/bin/fdautil</string>
  <string>exec</string>
  <string>/opt/bup/bup-recurring.sh</string>
 </array>
 <key>RunAtLoad</key>
 <true/>
 <key>StandardErrorPath</key>
 <string>/tmp/local.bup.job.stderr</string>
 <key>StandardOutPath</key>
 <string>/tmp/local.bup.job.stdout</string>
 <key>StartCalendarInterval</key>
 <array>
  <dict>
   <key>Hour</key>
   <integer>0</integer>
   <key>Minute</key>
   <integer>0</integer>
  </dict>
  <dict>
   <key>Hour</key>
   <integer>8</integer>
   <key>Minute</key>
   <integer>0</integer>
  </dict>
  <dict>
   <key>Hour</key>
   <integer>12</integer>
   <key>Minute</key>
   <integer>0</integer>
  </dict>
  <dict>
   <key>Hour</key>
   <integer>16</integer>
   <key>Minute</key>
   <integer>0</integer>
  </dict>
  <dict>
   <key>Hour</key>
   <integer>20</integer>
   <key>Minute</key>
   <integer>0</integer>
  </dict>
  <dict>
   <key>Hour</key>
   <integer>23</integer>
   <key>Minute</key>
   <integer>0</integer>
  </dict>
 </array>
</dict>
</plist>
```

## Cleaning up

If we don't periodically clean up older backups, Bup will, eventually, fill up the storage.

In my experience, removing old backups is the most dangerous (and probably less documented and tested) operation in Bup.
So, I recommend taking a volume snapshot on your NAS before attempting it.

Before taking the volume snapshot stop Bup:

```sh
docker stop bup
docker rm bup
```

Once the snapshot is complete, restart Bup without exposing it to the network:

```sh
docker run -d \
  -it \
  --name bup \
  --mount type=bind,source="/share/Bup/backups",target=/bup \
  dguerri/bup:v0.32r3
```

Log into the container:

```sh
docker exec -it bup bash
```

And run `screen` or `tmux` to make sure we can recover the session in case we lost connectivity and because clean-ups will take a long time if you have numerous backups.

For instance, run the following command to:

- Keep all the snapshots in the last 2 weeks;
- keep daily snapshots for the last month;
- keep monthly snapshots for the last 8 months;
- delete everything else.

You can add the `--pretend` flag to print the list of backup that will be kept and deleted.
The `--unsafe` flag is required as Bup developers wanted to make sure the user realize the risks of this operation.

```sh
bup prune-older --keep-all-for 2w \
                --keep-dailies-for 1m \
                --keep-monthlies-for 8m \
                -v --unsafe --pretend
```

Now remove the `--pretend` flag and be ready to wait several hours.
At the end of the operation, try to restore a few files before removing the safety volume snapshot.

Finally, don't forget to restart Bup as before:

```sh
docker stop bup
docker rm bup
docker run -d \
  -it \
  --name bup \
  --mount type=bind,source="/share/Bup/backups",target=/bup \
  -p 1982:1982 \
  dguerri/bup:v0.32r3
```

## Off-site data synchronization (disaster recovery)

This is completely optional, but if you are paranoid like me, you might want to send your data to somewhere safe, in case something happens to your NAS.

If your NAS supports it, you can easily configure a nightly job to mirror the local backup to a cloud storage provider like Backblaze or Amazon S3.
Alternatively, you can write some quick script. For instance:

- <https://serverfault.com/questions/754690/rsync-to-aws-s3-bucket>
- <https://help.backblaze.com/hc/en-us/articles/226937867-How-do-I-use-the-b2-sync-command>-

Going into the details of how to perform this off-site synchronization is beyond the scope of this article.
Nevertheless, I encourage the reader to consider encryption of data at rest on your local NAS and perform client-side encryption before sending data to the cloud.
Should the latter not be possible, at least make sure that your data is encrypted by the cloud provider.
