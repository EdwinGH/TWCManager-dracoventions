#! /usr/bin/python3

################################################################################
# Code and TWC protocol reverse engineering by Chris Dragon.
#
# Additional logs and hints provided by Teslamotorsclub.com users:
#   TheNoOne, IanAmber, and twc.
# Thank you!
#
# For support and information, please read through this thread:
# https://teslamotorsclub.com/tmc/threads/new-wall-connector-load-sharing-protocol.72830
#
#  Co-Author E Zuidema (simplified and adapted for own use)
#
# 2026-09-26 Fixed for 2 TWCs - reading the VINs, adding VIN to webmessage
#
# Report bugs at https://github.com/cdragon/TWCManager/issues
#
# This software is released under the "Unlicense" model: http://unlicense.org
# This means source code and TWC protocol knowledge are released to the general
# public free for personal or commercial use. I hope the knowledge will be used
# to increase the use of green energy sources by controlling the time and power
# level of car charging.
#
# WARNING:
# Misuse of the protocol described in this software can direct a Tesla Wall
# Charger to supply more current to a car than the charger wiring was designed
# for. This will trip a circuit breaker or may start a fire in the unlikely
# event that the circuit breaker fails.
# This software was not written or designed with the benefit of information from
# Tesla and there is always a small possibility that some unforeseen aspect of
# its operation could damage a Tesla vehicle or a Tesla Wall Charger. All
# efforts have been made to avoid such damage and this software is in active use
# on the author's own vehicle and TWC.
#
# In short, USE THIS SOFTWARE AT YOUR OWN RISK.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# For more information, please visit http://unlicense.org

progname = "TWCManager-edwin.py"
version  = "2026-11-21"

# Release 2020-07-28 Initial version
# Release 2026-09-13 Fixed some things for 2 TWCs (with 2 cars)
# Release 2026-11-16 Split the old TWCManagerSettings.txt in two.
#                    TWCManager_config.json holds everything you set by hand. It
#                    is JSON5, so the explanation of each parameter lives next to
#                    it as a comment, and TWCManager never writes to it.
#                    TWCManager_status.ini holds the values TWCManager changes by
#                    itself (nonScheduledAmpsMax from the web page, approvedVINs
#                    from the approve/revoke links, and kWhDelivered). Anything
#                    in the status file overrides the config file, so the config
#                    file holds the value you start from.
#                    Parsing JSON5 uses the json5 package when it is installed,
#                    and otherwise twc_json5.py, a small reader that ships next
#                    to this script and needs no package manager. Raspberry Pi OS
#                    Buster has neither python3-json5 nor pip3, which is why the
#                    fallback exists.
#                    Added -c/--config and -l/--log command line options; -l
#                    overrides debugLevel from the settings file.
#                    Fixed: approve/revoke from the web page called the
#                    non-existent save_vin_approvals(), so it raised NameError,
#                    never persisted the change and stalled the web interface.
#                    Fixed: only the last TWC was written to the database each
#                    round because the INSERT sat outside the per-TWC loop.
#                    Fixed: the "Query:" debug line used a comma instead of %,
#                    and is now gated on debugLevel.
#                    The 30-second status block is now gated on debugLevel >= 2
#                    and condensed to one line plus one per TWC, so the default
#                    level writes about one line every 10 seconds.
#                    Fixed: print_status looked for the amps with a pattern that
#                    stopped matching when the SHB line gained its TWCID and
#                    reportedState labels, so its repeat suppression never
#                    worked and every heartbeat printed, at any debugLevel.
# Release 2026-11-20 Fixed: TWCSlave.wiringMaxAmps was a class attribute set to
#                    wiringMaxAmpsPerTWC, which is evaluated when this file is
#                    imported, before load_config() runs. It therefore froze the
#                    fallback of 6A and capped every car at 6A no matter what
#                    the config file said. It is now set per instance in
#                    __init__.
#                    Fixed: an all zero VIN response, which a TWC sends when it
#                    cannot read the car (asleep, CAN quiet), replaced the VIN
#                    already recorded with an empty one. With blockUnknownVINs
#                    set that cut power to a car that was still plugged in. An
#                    empty read now keeps the VIN already held; only a valid
#                    17 character VIN replaces it.
#                    The "VIN not approved" message is no longer repeated on
#                    every heartbeat, only when the VIN changes or once a minute.
#                    blockUnknownVINs and displayMilliseconds are now parsed with
#                    config_bool, because bool("false") is True and a quoted
#                    value in the config file would have turned them on.
#                    load_config now logs the amp limits it ended up with.
#                    Reindented the whole file to 2 spaces per level. The
#                    upstream code used 4 and the newer parts used 2. Done from
#                    the token stream, so multi-line strings were left alone and
#                    continuation lines kept their alignment; verified by
#                    comparing the parsed AST before and after.
# Release 2026-11-20b Fixed: restarting TWCManager cut an approved car to 0A,
#                    because blockUnknownVINs applied before the first VIN read
#                    had finished, and the 60 second restart guard then held the
#                    car off for a full minute. The check now waits for a
#                    completed VIN read, or VIN_GRACE_SECONDS if the TWC never
#                    answers.
#                    "Assigning VIN" is no longer logged with a blank VIN, and
#                    the "cars charging" debug line now names the TWC and says
#                    the count includes that TWC itself.
# Release 2026-11-21 Reworked when the VIN is trusted, after the 20 November
#                    version held on to the VIN of a car that had been
#                    unplugged and driven away.
#                    An empty VIN read clears the VIN again, so the web page
#                    and the database stop showing a car that has gone. The
#                    protocol gives no way to tell a sleeping plugged in car
#                    from an empty charger, so instead of guessing:
#                      - blockUnknownVINs is only enforced while the TWC
#                        reports a state other than 0. No current can flow at
#                        state 0, so nothing is gained by blocking there and an
#                        approved car that is merely asleep is not cut off.
#                      - leaving state 0 triggers an immediate VIN re-read, with
#                        the grace period applied again, so a car that wakes or
#                        a different car that is plugged in is identified within
#                        a few seconds without losing a minute to the restart
#                        guard.
# Release 2026-11-21b Fixed: a car that had just been plugged in was offered 0A
#                    for about 13 seconds, because its first VIN read after
#                    becoming active returns all zeros while the car is still
#                    waking, and that counted as "identified". Only a real VIN
#                    ends the grace period now; a car that never answers is
#                    still blocked when the grace period runs out.
#                    The "Offering slave TWC ... instead of ..." warning no
#                    longer prints when the clamp changed nothing.

# TODO: Remove web interface? Add MQTT?

# TWC ReportedState (heartbeatData[0]) seen so far and interpretation:
# 0 - No car plugged in (or car asleep?!)
# 1 - Plugged in and Charging (sometimes alternated with 9)
# 3 - Plugged in and not Charging
# 8 - Plugged in and Charging (before and after state 9?)
# 9 - Plugged in and Charging (ready to charge? changing state? Seeing first 8 (optional) then 9 then 1 on starting charge)

################################################################################
# What's TWCManager good for?
#
# This script (TWCManager) pretends to be a Tesla Wall Charger (TWC) set to
# master mode. When wired to the IN or OUT pins of real TWC units set to slave
# mode (rotary switch position F), TWCManager can tell them to limit car
# charging to any whole amp value between 5A and the max rating of the charger.
# Charging can also be stopped so the car goes to sleep.
#
# One thing TWCManager does not have direct access to is the battery charge
# percentage of each plugged-in car. There are hints on forums that some TWCs
# do report battery state, but we have yet to see a TWC send such a message.
# It's possible the feature exists in TWCs with newer firmware.
# This is unfortunate, but if you own a Tesla vehicle being charged, people have
# figured out how to get its charge state by contacting Tesla's servers using
# the same password you use in the Tesla phone app. Be very careful not to
# expose that password because it allows unlocking and starting the car.

################################################################################
# Overview of protocol TWCs use to load share
#
# A TWC set to slave mode (rotary switch position F) sends a linkready message
# every 10 seconds.
# The message contains a unique 4-byte id that identifies that particular slave
# as the sender of the message.
#
# A TWC set to master mode sees a linkready message. In response, it sends a
# heartbeat message containing the slave's 4-byte id as the intended recipient
# of the message.
# The master's 4-byte id is included as the sender of the message.
#
# Slave sees a heartbeat message from master directed to its unique 4-byte id
# and responds with its own heartbeat message containing the master's 4-byte id
# as the intended recipient of the message.
# The slave's 4-byte id is included as the sender of the message.
#
# Master sends a heartbeat to a slave around once per second and expects a
# response heartbeat from the slave.
# Slaves do not send heartbeats without seeing one from a master first. If
# heartbeats stop coming from master, slave resumes sending linkready every 10
# seconds.
# If slaves stop replying to heartbeats from master, master stops sending
# heartbeats after about 26 seconds.
#
# Heartbeat messages contain a data block used to negotiate the amount of power
# available to each slave and to the master.
# The first byte is a status indicating things like is TWC plugged in, does it
# want power, is there an error, etc.
# Next two bytes indicate the amount of power requested or the amount allowed in
# 0.01 amp increments.
# Next two bytes indicate the amount of power being used to charge the car, also in
# 0.01 amp increments.
# Remaining bytes always contain a value of 0.

# EZ added MySQL logging
# MySQL database:
# CREATE TABLE `twc_data` (
# `timestamp` DATETIME,
# `total_amps_max` FLOAT(10,7) NULL DEFAULT NULL,
# `twc_id` VARCHAR(64),
# `amps_offered` FLOAT(10,7) NULL DEFAULT NULL,
# `current_amps` FLOAT(10,7) NULL DEFAULT NULL,
# `state` TINYINT(3) UNSIGNED NULL DEFAULT NULL,
#
# PRIMARY KEY (`timestamp`, `twc_id`)
# );

import os
import serial
import time
import re
import subprocess
import queue
import random
import math
import struct
import sys
import traceback
import sysv_ipc
import json
import argparse
import configparser
from datetime import datetime
import mysql.connector

# TWCManager_config.json is JSON5 so that each setting can carry its explanation
# as a comment. Plain json cannot read that, so use the json5 package when it is
# installed and otherwise twc_json5.py, the small reader that ships next to this
# script. Installing the package later needs no change here.
try:
  import json5
except ImportError:
  # Make sure the script's own directory is searched, whatever the working
  # directory and whatever symlink the script was started through
  sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
  try:
    import twc_json5 as json5
  except ImportError:
    print("ERROR: no JSON5 reader found, so TWCManager_config.json cannot be read.")
    print("Put twc_json5.py next to this script, or install the json5 package:")
    print("    sudo pip3 install json5")
    print("    (Debian 12 and later: sudo apt install python3-json5)")
    sys.exit(1)


##########################
#
# Configuration parameters
#
# All configuration now lives in TWCManager_settings.json, which is JSON5 so
# that the explanation of each parameter sits next to it as a comment. See that
# file for what every setting below means.
#
# The values here are only fallbacks used when a setting is missing from the
# settings file; load_config() overwrites them at startup. Edit the JSON file,
# not this block.
#

# RS-485 interface
rs485Adapter = '/dev/ttyUSB0'
baud = 9600

# Wiring limits (amps). Deliberately low defaults: a missing setting must never
# silently raise the current we ask the chargers to draw.
wiringMaxAmpsAllTWCs = 6
wiringMaxAmpsPerTWC = 6
minAmpsPerTWC = 6

# Mains supply, used to estimate the kWh delivered in master mode
supplyVolts = 230
supplyPhases = 3

# Offer 0A to a car that reports no VIN at all
blockUnknownVINs = False

# Operating mode: 1 = fake master, 0 = fake slave, 2 = listen only
fakeMaster = 1
fakeTWCID = bytearray(b'\x77\x77')
masterSign = bytearray(b'\x77')
slaveSign = bytearray(b'\x77')

# Logging
debugLevel = 2
displayMilliseconds = False

# Directory whose inode gives the SysV IPC key shared with the web interface
webIPCDir = '/home/pi/TWCManager-dracoventions'

# MySQL logging
mysql_user = ''
mysql_passwd = ''
mysql_host = ''
mysql_database = ''

#
# End configuration parameters
#
##############################



##############################
#
# Begin global vars
#

overrideMasterHeartbeatData = b''

masterTWCID = ''
slaveHeartbeatData = bytearray([0x01,0x0F,0xA0,0x0F,0xA0,0x00,0x00,0x00,0x00])
timeLastTx = 0

slaveTWCs = {}
slaveTWCRoundRobin = []

maxAmpsToDivideAmongSlaves = 0

chargeNowAmps = 0
chargeNowTimeEnd = 0

spikeAmpsToCancel6ALimit = 16
kWhDelivered = 0

# How long after a slave TWC first appears we wait for it to report a VIN
# before blockUnknownVINs is allowed to cut its car off. Covers a TWC that
# never answers at all.
VIN_GRACE_SECONDS = 30

# Read-only settings you edit by hand. TWCManager never writes to this file.
configFileName = 'TWCManager_config.json'

# Settings TWCManager changes by itself. Written whenever one of them changes,
# and read after the config file so that what is here wins.
statusFileName = 'TWCManager_status.ini'

nonScheduledAmpsMax = -1

# vin -> expiry unix time, 0 means forever
approvedVINs = {}

ser = None

#
# End global vars
#
##############################



##############################
#
# Begin functions
#

def time_now():
  global displayMilliseconds
  return(datetime.now().strftime("%H:%M:%S" + (
      ".%f" if displayMilliseconds else "")))

def hex_str(s:str):
  return " ".join("{:02X}".format(ord(c)) for c in s)

def hex_str(ba:bytearray):
  return " ".join("{:02X}".format(c) for c in ba)

def run_process(cmd):
  result = None
  try:
    result = subprocess.check_output(cmd, shell=True)
  except subprocess.CalledProcessError:
    # We reach this point if the process returns a non-zero exit code.
    result = b''

  return result


def resolve_path(name):
  # Resolve a relative file name against the directory holding this script, so
  # the settings and status files are found whatever the working directory is
  if(os.path.isabs(name)):
    return name
  return os.path.join(os.path.dirname(os.path.realpath(__file__)), name)


def write_file_atomic(name, content):
  # Write via a temp file and rename so a crash or power cut cannot leave a
  # half-written file. Renaming needs write permission on the directory, so fall
  # back to writing in place if that is refused.
  tmpName = name + '.tmp'
  try:
    with open(tmpName, 'w') as fh:
      fh.write(content)
      fh.flush()
      os.fsync(fh.fileno())
    os.replace(tmpName, name)
    return True
  except Exception as e:
    print(time_now() + ": Atomic write of %s failed (%s), writing in place" % (name, e))

  try:
    if(os.path.exists(tmpName)):
      os.remove(tmpName)
  except Exception:
    pass

  try:
    with open(name, 'w') as fh:
      fh.write(content)
      fh.flush()
      os.fsync(fh.fileno())
    return True
  except Exception as e:
    print(time_now() + ": Could not write %s: %s" % (name, e))
    return False


def config_get(cfg, key, fallback):
  # Return cfg[key] when the config file has it, else the fallback already in
  # this script, saying so once at startup
  if(key in cfg):
    return cfg[key]
  print(time_now() + ": load_config: '%s' missing from %s, using %s"
        % (key, configFileName, repr(fallback)))
  return fallback


def config_number(cfg, key, fallback):
  # Return a numeric setting, leaving an int an int so log lines and the web
  # interface see exactly the values they saw before
  value = config_get(cfg, key, fallback)
  if(isinstance(value, bool) or not isinstance(value, (int, float))):
    print(time_now() + ": load_config: '%s' is not a number, using %s"
          % (key, repr(fallback)))
    return fallback
  return value


def config_bool(cfg, key, fallback):
  # Return a true/false setting. json5 gives a real bool for true and false, but
  # a value that was written in quotes arrives as a string, and bool("false") is
  # True, which would silently turn a setting on.
  value = config_get(cfg, key, fallback)
  if(isinstance(value, bool)):
    return value
  if(isinstance(value, str)):
    if(value.strip().lower() in ('true', 'yes', 'on', '1')):
      return True
    if(value.strip().lower() in ('false', 'no', 'off', '0', '')):
      return False
  if(isinstance(value, (int, float))):
    return (value != 0)
  print(time_now() + ": load_config: '%s' is not true or false, using %s"
        % (key, repr(fallback)))
  return fallback


def load_config():
  # Read TWCManager_config.json. A broken config file is fatal: running on
  # fallback wiring limits with nothing approved would be worse than not running.
  # Values that TWCManager maintains itself are read afterwards by load_status(),
  # which overrides what is set here.
  global configFileName, statusFileName
  global rs485Adapter, baud
  global wiringMaxAmpsAllTWCs, wiringMaxAmpsPerTWC, minAmpsPerTWC
  global supplyVolts, supplyPhases
  global blockUnknownVINs, fakeMaster, fakeTWCID, masterSign, slaveSign
  global debugLevel, displayMilliseconds, webIPCDir
  global mysql_user, mysql_passwd, mysql_host, mysql_database
  global nonScheduledAmpsMax, approvedVINs

  try:
    with open(configFileName, 'r') as fh:
      cfg = json5.load(fh)
  except FileNotFoundError:
    print(time_now() + ": ERROR: Config file %s not found." % configFileName)
    sys.exit(1)
  except Exception as e:
    print(time_now() + ": ERROR: Could not parse %s: %s" % (configFileName, e))
    sys.exit(1)

  if(not isinstance(cfg, dict)):
    print(time_now() + ": ERROR: %s must contain a JSON object." % configFileName)
    sys.exit(1)

  rs485Adapter = str(config_get(cfg, 'rs485Adapter', rs485Adapter))
  baud = int(config_get(cfg, 'baud', baud))

  wiringMaxAmpsAllTWCs = config_number(cfg, 'wiringMaxAmpsAllTWCs', wiringMaxAmpsAllTWCs)
  wiringMaxAmpsPerTWC = config_number(cfg, 'wiringMaxAmpsPerTWC', wiringMaxAmpsPerTWC)
  minAmpsPerTWC = config_number(cfg, 'minAmpsPerTWC', minAmpsPerTWC)

  supplyVolts = config_number(cfg, 'supplyVolts', supplyVolts)
  supplyPhases = int(config_get(cfg, 'supplyPhases', supplyPhases))

  blockUnknownVINs = config_bool(cfg, 'blockUnknownVINs', blockUnknownVINs)
  fakeMaster = int(config_get(cfg, 'fakeMaster', fakeMaster))

  fakeTWCID = bytearray.fromhex(str(config_get(cfg, 'fakeTWCID', '7777')))
  masterSign = bytearray.fromhex(str(config_get(cfg, 'masterSign', '77')))
  slaveSign = bytearray.fromhex(str(config_get(cfg, 'slaveSign', '77')))

  debugLevel = int(config_get(cfg, 'debugLevel', debugLevel))
  displayMilliseconds = config_bool(cfg, 'displayMilliseconds', displayMilliseconds)

  webIPCDir = str(config_get(cfg, 'webIPCDir', webIPCDir))

  mysql_user = str(config_get(cfg, 'mysql_user', mysql_user))
  mysql_passwd = str(config_get(cfg, 'mysql_passwd', mysql_passwd))
  mysql_host = str(config_get(cfg, 'mysql_host', mysql_host))
  mysql_database = str(config_get(cfg, 'mysql_database', mysql_database))

  statusFileName = resolve_path(str(config_get(cfg, 'statusFileName', statusFileName)))

  # Starting values for the two settings the web interface can change. Whatever
  # is in the status file replaces these.
  nonScheduledAmpsMax = int(config_get(cfg, 'nonScheduledAmpsMax', nonScheduledAmpsMax))

  approvedVINs = dict(config_get(cfg, 'approvedVINs', {}))

  # fakeTWCID cannot sensibly be guessed, so refuse to run on the fallback
  if(len(fakeTWCID) != 2):
    print(time_now() + ": ERROR: fakeTWCID must be two hex bytes, eg \"7777\".")
    sys.exit(1)
  if(wiringMaxAmpsAllTWCs < minAmpsPerTWC):
    print(time_now() + ": WARNING: wiringMaxAmpsAllTWCs (%.2f) is below "
          "minAmpsPerTWC (%.2f), so no car will ever be offered power."
          % (wiringMaxAmpsAllTWCs, minAmpsPerTWC))

  if(debugLevel >= 2):
    print(time_now() + ": Loaded config from " + configFileName)
    print(time_now() + ": Limits: %.2fA all TWCs, %.2fA per TWC, %.2fA minimum, "
          "blockUnknownVINs %s"
          % (wiringMaxAmpsAllTWCs, wiringMaxAmpsPerTWC, minAmpsPerTWC,
             blockUnknownVINs))


def prune_expired_vins():
  # Drop VIN approvals whose expiry time has passed
  global approvedVINs

  now = time.time()
  for vin in list(approvedVINs.keys()):
    if(approvedVINs[vin] != 0 and approvedVINs[vin] < now):
      del approvedVINs[vin]


def load_status():
  # Read TWCManager_status.ini, which holds the settings TWCManager changes by
  # itself. Anything found here replaces what the config file said.
  global statusFileName, kWhDelivered, nonScheduledAmpsMax, approvedVINs, debugLevel

  if(not os.path.exists(statusFileName)):
    # Nothing saved yet, so the config file's values stand. The first save
    # writes the file.
    print(time_now() + ": No %s yet, using the values from %s"
          % (statusFileName, configFileName))
    prune_expired_vins()
    return

  parser = configparser.ConfigParser()
  # Keep VINs in the case they were written in
  parser.optionxform = str
  try:
    parser.read(statusFileName)
  except Exception as e:
    print(time_now() + ": Could not read %s: %s" % (statusFileName, e))
    print(time_now() + ": Keeping the values from " + configFileName)
    prune_expired_vins()
    return

  if(parser.has_option('settings', 'nonScheduledAmpsMax')):
    try:
      nonScheduledAmpsMax = int(parser.get('settings', 'nonScheduledAmpsMax'))
    except ValueError as e:
      print(time_now() + ": Bad nonScheduledAmpsMax in %s: %s" % (statusFileName, e))

  if(parser.has_option('state', 'kWhDelivered')):
    try:
      kWhDelivered = float(parser.get('state', 'kWhDelivered'))
    except ValueError as e:
      print(time_now() + ": Bad kWhDelivered in %s: %s" % (statusFileName, e))

  # An approvedVINs section replaces the list from the config file entirely, so
  # that revoking the last car really does leave nothing approved
  if(parser.has_section('approvedVINs')):
    vins = {}
    for (vin, expiry) in parser.items('approvedVINs'):
      try:
        # Whole numbers stay ints so the logs read the same as the file
        value = float(expiry)
        vins[vin] = int(value) if value == int(value) else value
      except ValueError:
        print(time_now() + ": Bad expiry for VIN %s in %s, ignoring it"
              % (vin, statusFileName))
    approvedVINs = vins

  prune_expired_vins()

  if(debugLevel >= 2):
    print(time_now() + ": Loaded status from " + statusFileName)
    print(time_now() + ": nonScheduledAmpsMax %d, kWhDelivered %.3f"
          % (nonScheduledAmpsMax, kWhDelivered))
    print(time_now() + ": Approved VINs: " + str(approvedVINs))


def save_status():
  # Write TWCManager_status.ini. Called whenever one of these values changes, so
  # nothing is lost on a power failure or a restart.
  global statusFileName, kWhDelivered, nonScheduledAmpsMax, approvedVINs

  lines = []
  lines.append('# TWCManager status')
  lines.append('#')
  lines.append('# WRITTEN BY TWCManager. Do not edit while the service is running:')
  lines.append('# your changes would be overwritten the next time it saves.')
  lines.append('#')
  lines.append('# These are the settings TWCManager changes by itself, from the web')
  lines.append('# interface or while charging. Everything here OVERRIDES the matching')
  lines.append('# setting in %s, which holds the value to' % os.path.basename(configFileName))
  lines.append('# start from. To go back to that starting value, stop TWCManager, delete')
  lines.append('# the entry here (or the whole file), and start it again.')
  lines.append('#')
  lines.append('# Last written %s' % datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
  lines.append('')
  lines.append('[settings]')
  lines.append('# Amps offered when no charging schedule is active, -1 to track green')
  lines.append('# energy. Set from the "(Non-scheduled) Power" dropdown on the web page.')
  lines.append('nonScheduledAmpsMax = %d' % nonScheduledAmpsMax)
  lines.append('')
  lines.append('[state]')
  lines.append('# Running total of the energy delivered to cars, in kWh.')
  lines.append('kWhDelivered = %s' % kWhDelivered)
  lines.append('')
  lines.append('[approvedVINs]')
  lines.append('# Cars allowed to charge: VIN = expiry, where 0 means forever and any')
  lines.append('# other number is a unix time. Set from the [always] / [24h] / [revoke]')
  lines.append('# links on the web page. An empty section means nothing is approved.')
  for vin in sorted(approvedVINs.keys()):
    expiry = approvedVINs[vin]
    # Whole numbers are written without a decimal point to keep the file tidy
    if(float(expiry) == int(expiry)):
      lines.append('%s = %d' % (vin, int(expiry)))
    else:
      lines.append('%s = %s' % (vin, expiry))
  lines.append('')

  write_file_atomic(statusFileName, '\n'.join(lines))


def parse_arguments():
  # Command line options. Anything given here wins over the config file.
  parser = argparse.ArgumentParser(description='Tesla Wall Charger Manager',
                                   epilog='Co-Author E. Zuidema')
  parser.add_argument('-c', '--config',
                      help="Config file to read, default "
                           "'TWCManager_config.json' next to this script")
  parser.add_argument('-l', '--log', type=str.lower,
                      help="Logging level: 'none', 'warning', 'info', 'debug' or "
                           "'all'. Overrides debugLevel from the config file.")
  args = parser.parse_args()

  levels = {'none': 0, 'error': 0, 'warning': 1, 'info': 2, 'debug': 10, 'all': 20}
  level = None
  if(args.log is not None):
    if(args.log not in levels):
      parser.error("Unknown log level '%s'" % args.log)
    level = levels[args.log]

  return (args.config, level)


def vin_approved(vin):
  global approvedVINs, blockUnknownVINs
  if vin == "":
    # No VIN reported: car asleep, CAN disabled, or TWC hasn't answered yet
    return not blockUnknownVINs
  expiry = approvedVINs.get(vin)
  if expiry is None:
    return False
  if expiry == 0:
    return True
  return time.time() < expiry

def trim_pad(s:bytearray, makeLen):
  # Trim or pad s with zeros so that it's makeLen length.
  while(len(s) < makeLen):
    s += b'\x00'

  if(len(s) > makeLen):
    s = s[0:makeLen]

  return s


def send_msg(msg):
  # Send msg on the RS485 network. We'll escape bytes with a special meaning,
  # add a CRC byte to the message end, and add a C0 byte to the start and end
  # to mark where it begins and ends.
  global ser, timeLastTx, fakeMaster, slaveTWCRoundRobin

  msg = bytearray(msg)
  checksum = 0
  for i in range(1, len(msg)):
    checksum += msg[i]

  msg.append(checksum & 0xFF)

  # Escaping special chars:
  # The protocol uses C0 to mark the start and end of the message.  If a C0
  # must appear within the message, it is 'escaped' by replacing it with
  # DB and DC bytes.
  # A DB byte in the message is escaped by replacing it with DB DD.
  #
  # User FuzzyLogic found that this method of escaping and marking the start
  # and end of messages is based on the SLIP protocol discussed here:
  #   https://en.wikipedia.org/wiki/Serial_Line_Internet_Protocol
  i = 0
  while(i < len(msg)):
    if(msg[i] == 0xc0):
      msg[i:i+1] = b'\xdb\xdc'
      i = i + 1
    elif(msg[i] == 0xdb):
      msg[i:i+1] = b'\xdb\xdd'
      i = i + 1
    i = i + 1

  msg = bytearray(b'\xc0' + msg + b'\xc0')

  if(debugLevel >= 9):
    print("Tx@" + time_now() + ": " + hex_str(msg))

  ser.write(msg)

  timeLastTx = time.time()

def unescape_msg(msg:bytearray, msgLen):
  # Given a message received on the RS485 network, remove leading and trailing
  # C0 byte, unescape special byte values, and verify its data matches the CRC
  # byte.
  # EZ added cast to bytearray after errors
  msg = bytearray(msg[0:msgLen])
    
  # See notes in send_msg() for the way certain bytes in messages are escaped.
  # We basically want to change db dc into c0 and db dd into db.
  # Only scan to one less than the length of the string to avoid running off
  # the end looking at i+1.
  i = 0
  while i < len(msg):
    if(msg[i] == 0xdb):
      if(msg[i+1] == 0xdc):
        # Replace characters at msg[i] and msg[i+1] with 0xc0,
        # shortening the string by one character. In Python, msg[x:y]
        # refers to a substring starting at x and ending immediately
        # before y. y - x is the length of the substring.
        msg[i:i+2] = [0xc0]
      elif(msg[i+1] == 0xdd):
        msg[i:i+2] = [0xdb]
      else:
        print(time_now(), "ERROR: Special character 0xDB in message is " \
          "followed by invalid character 0x%02X.  " \
          "Message may be corrupted." %
          (msg[i+1]))

        # Replace the character with something even though it's probably
        # not the right thing.
        msg[i:i+2] = [0xdb]
    i = i+1

  # Remove leading and trailing C0 byte.
  msg = msg[1:len(msg)-1]
  return msg


def send_master_linkready1():
  if(debugLevel >= 1):
    print(time_now() + ": Send master linkready1")

  # When master is powered on or reset, it sends 5 to 7 copies of this
  # linkready1 message followed by 5 copies of linkready2 (I've never seen
  # more or less than 5 of linkready2).
  #
  # This linkready1 message advertises master's TWCID to other slaves on the
  # network.
  # If a slave happens to have the same id as master, it will pick a new
  # random TWCID. Other than that, slaves don't seem to respond to linkready1.

  # linkready1 and linkready2 are identical except FC E1 is replaced by FB E2
  # in bytes 2-3. Both messages will cause a slave to pick a new id if the
  # slave's id conflicts with master.
  # If a slave stops sending heartbeats for awhile, master may send a series
  # of linkready1 and linkready2 messages in seemingly random order, which
  # means they don't indicate any sort of startup state.

  # linkready1 is not sent again after boot/reset unless a slave sends its
  # linkready message.
  # At that point, linkready1 message may start sending every 1-5 seconds, or
  # it may not be sent at all.
  # Behaviors I've seen:
  #   Not sent at all as long as slave keeps responding to heartbeat messages
  #   right from the start.
  #   If slave stops responding, then re-appears, linkready1 gets sent
  #   frequently.

  # One other possible purpose of linkready1 and/or linkready2 is to trigger
  # an error condition if two TWCs on the network transmit those messages.
  # That means two TWCs have rotary switches setting them to master mode and
  # they will both flash their red LED 4 times with top green light on if that
  # happens.

  # Also note that linkready1 starts with FC E1 which is similar to the FC D1
  # message that masters send out every 4 hours when idle. Oddly, the FC D1
  # message contains all zeros instead of the master's id, so it seems
  # pointless.

  # I also don't understand the purpose of having both linkready1 and
  # linkready2 since only two or more linkready2 will provoke a response from
  # a slave regardless of whether linkready1 was sent previously. Firmware
  # trace shows that slaves do something somewhat complex when they receive
  # linkready1 but I haven't been curious enough to try to understand what
  # they're doing. Tests show neither linkready1 or 2 are necessary. Slaves
  # send slave linkready every 10 seconds whether or not they got master
  # linkready1/2 and if a master sees slave linkready, it will start sending
  # the slave master heartbeat once per second and the two are then connected.
  send_msg(bytearray(b'\xFC\xE1') + fakeTWCID + masterSign + bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00'))


def send_master_linkready2():
  if(debugLevel >= 1):
    print(time_now() + ": Send master linkready2")

  # This linkready2 message is also sent 5 times when master is booted/reset
  # and then not sent again if no other TWCs are heard from on the network.
  # If the master has ever seen a slave on the network, linkready2 is sent at
  # long intervals.
  # Slaves always ignore the first linkready2, but respond to the second
  # linkready2 around 0.2s later by sending five slave linkready messages.
  #
  # It may be that this linkready2 message that sends FB E2 and the master
  # heartbeat that sends fb e0 message are really the same, (same FB byte
  # which I think is message type) except the E0 version includes the TWC ID
  # of the slave the message is intended for whereas the E2 version has no
  # recipient TWC ID.
  #
  # Once a master starts sending heartbeat messages to a slave, it
  # no longer sends the global linkready2 message (or if it does,
  # they're quite rare so I haven't seen them).
  send_msg(bytearray(b'\xFB\xE2') + fakeTWCID + masterSign + bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00'))

def send_slave_linkready():
  # In the message below, \x1F\x40 (hex 0x1f40 or 8000 in base 10) refers to
  # this being a max 80.00Amp charger model.
  # EU chargers are 32A and send 0x0c80 (3200 in base 10).
  #
  # I accidentally changed \x1f\x40 to \x2e\x69 at one point, which makes the
  # master TWC immediately start blinking its red LED 6 times with top green
  # LED on. Manual says this means "The networked Wall Connectors have
  # different maximum current capabilities".
  msg = bytearray(b'\xFD\xE2') + fakeTWCID + slaveSign + bytearray(b'\x1F\x40\x00\x00\x00\x00\x00\x00')
  if(self.protocolVersion == 2):
    msg += bytearray(b'\x00\x00')

  send_msg(msg)

# EZ Added
def getVehicleVIN(slaveID, part):
  prefixByte = None
  if int(part) == 0:
    prefixByte = bytearray(b"\xFB\xEE")
  if int(part) == 1:
    prefixByte = bytearray(b"\xFB\xEF")
  if int(part) == 2:
    prefixByte = bytearray(b"\xFB\xF1")

  if prefixByte:
    send_msg(
        prefixByte
        + fakeTWCID
        + slaveID
        + bytearray(b"\x00\x00\x00\x00\x00\x00\x00\x00")
    )


def master_id_conflict():
  # We're playing fake slave, and we got a message from a master with our TWCID.
  # By convention, as a slave we must change our TWCID because a master will not.
  fakeTWCID[0] = random.randint(0, 0xFF)
  fakeTWCID[1] = random.randint(0, 0xFF)

  # Real slaves change their sign during a conflict, so we do too.
  slaveSign[0] = random.randint(0, 0xFF)

  print(time_now() + ": Master's TWCID matches our fake slave's TWCID.  " \
      "Picked new random TWCID %02X%02X with sign %02X" % \
      (fakeTWCID[0], fakeTWCID[1], slaveSign[0]))

def new_slave(newSlaveID, maxAmps):
  global slaveTWCs, slaveTWCRoundRobin

  try:
    slaveTWC = slaveTWCs[newSlaveID]
    # We didn't get KeyError exception, so this slave is already in
    # slaveTWCs and we can simply return it.
    return slaveTWC
  except KeyError:
    pass

  slaveTWC = TWCSlave(newSlaveID, maxAmps)
  slaveTWCs[newSlaveID] = slaveTWC
  slaveTWCRoundRobin.append(slaveTWC)

  if(len(slaveTWCRoundRobin) > 3):
    print("WARNING: More than 3 slave TWCs seen on network.  " \
        "Dropping oldest: " + hex_str(slaveTWCRoundRobin[0].TWCID) + ".")
    delete_slave(slaveTWCRoundRobin[0].TWCID)

  return slaveTWC

def delete_slave(deleteSlaveID):
  global slaveTWCs, slaveTWCRoundRobin

  for i in range(0, len(slaveTWCRoundRobin)):
    if(slaveTWCRoundRobin[i].TWCID == deleteSlaveID):
      del slaveTWCRoundRobin[i]
      break
  try:
    del slaveTWCs[deleteSlaveID]
  except KeyError:
    pass

def total_amps_actual_all_twcs():
  global debugLevel, slaveTWCRoundRobin, wiringMaxAmpsAllTWCs

  totalAmps = 0
  for slaveTWC in slaveTWCRoundRobin:
    totalAmps += slaveTWC.reportedAmpsActual
  if(debugLevel >= 10):
    print("Total amps all slaves are using: " + str(totalAmps))
  return totalAmps


#
# End functions
#
##############################


##############################
#
# Begin TWCSlave class
#

class TWCSlave:
  TWCID = None
  maxAmps = None

  # Protocol 2 TWCs tend to respond to commands sent using protocol 1, so
  # default to that till we know for sure we're talking to protocol 2.
  protocolVersion = 1
  minAmpsTWCSupports = 6
  masterHeartbeatData = bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00')
  timeLastRx = time.time()

  # reported* vars below are reported to us in heartbeat messages from a Slave
  # TWC.
  reportedAmpsMax = 0
  reportedAmpsActual = 0
  reportedState = 0

  # reportedAmpsActual frequently changes by small amounts, like 5.14A may
  # frequently change to 5.23A and back.
  # reportedAmpsActualSignificantChangeMonitor is set to reportedAmpsActual
  # whenever reportedAmpsActual is at least 0.8A different than
  # reportedAmpsActualSignificantChangeMonitor. Whenever
  # reportedAmpsActualSignificantChangeMonitor is changed,
  # timeReportedAmpsActualChangedSignificantly is set to the time of the
  # change. The value of reportedAmpsActualSignificantChangeMonitor should not
  # be used for any other purpose. timeReportedAmpsActualChangedSignificantly
  # is used for things like preventing start and stop charge on a car more
  # than once per minute.
  reportedAmpsActualSignificantChangeMonitor = -1
  timeReportedAmpsActualChangedSignificantly = time.time()

  lastAmpsOffered = -1
  timeLastAmpsOfferedChanged = time.time()
  lastHeartbeatDebugOutput = ''
  timeLastHeartbeatDebugOutput = 0
  # Set per instance in __init__, NOT here. A class attribute is evaluated
  # when this file is imported, which is before load_config() has run, so it
  # would freeze the fallback value and ignore the config file.
  wiringMaxAmps = 0
  # EZ Added
  lifetimekWh = 0
  voltsPhaseA = 0
  voltsPhaseB = 0
  voltsPhaseC = 0
  currentVIN = ""


  def __init__(self, TWCID, maxAmps):
    self.TWCID = TWCID
    self.maxAmps = maxAmps
    self.VINData = ["", "", ""]
    self.masterHeartbeatData = bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    self.timeLastVINRequest = 0
    # Read here rather than as a class attribute, so the value comes from
    # the config file instead of the fallback in force at import time
    self.wiringMaxAmps = wiringMaxAmpsPerTWC
    # Used to keep the "VIN not approved" message from repeating every
    # heartbeat
    self.lastVINRefused = None
    self.timeLastVINRefusedPrint = 0
    # When this slave was first seen, and whether a VIN read has completed for
    # it. Until one of those says otherwise we do not block the car: at startup
    # the VIN is always empty for a second or so, and offering 0A there costs a
    # minute to the restart guard in receive_slave_heartbeat.
    self.timeFirstSeen = time.time()
    self.vinReadDone = False

  def print_status(self, heartbeatData):
    global fakeMaster, masterTWCID

    try:
      debugOutput = ": SHB TWCID %02X%02X: reportedState %02X ActualAmps/MaxAmps %05.2f/%05.2fA HB5 %02X HB6 %02X" % \
          (self.TWCID[0], self.TWCID[1], heartbeatData[0],
          (((heartbeatData[3] << 8) + heartbeatData[4]) / 100),
          (((heartbeatData[1] << 8) + heartbeatData[2]) / 100),
          heartbeatData[5], heartbeatData[6]
          )
      if(self.protocolVersion == 2):
        debugOutput += (" %02X%02X" % (heartbeatData[7], heartbeatData[8]))
      debugOutput += "  MHB"

      if(not fakeMaster):
        debugOutput += " TWCID %02X%02X" % (masterTWCID[0], masterTWCID[1])

      debugOutput += ": reportedState %02X ActualAmps/MaxAmps %05.2f/%05.2fA HB5 %02X HB6 %02X" % \
              (self.masterHeartbeatData[0],
              (((self.masterHeartbeatData[3] << 8) + self.masterHeartbeatData[4]) / 100),
              (((self.masterHeartbeatData[1] << 8) + self.masterHeartbeatData[2]) / 100),
              self.masterHeartbeatData[5], self.masterHeartbeatData[6])
      if(self.protocolVersion == 2):
        debugOutput += (" HB7 %02X HB8 %02X" %
            (self.masterHeartbeatData[7], self.masterHeartbeatData[8]))

      # Only output once-per-second heartbeat debug info when it's
      # different from the last output or if the only change has been amps
      # in use and it's only changed by 1.0 or less. Also output f it's
      # been 10 mins since the last output or if debugLevel is turned up
      # to 11.
      # The pattern must match the SHB text built above. If it does not,
      # ampsUsed and lastAmpsUsed keep their starting values, the test
      # below is always true and every heartbeat prints.
      ampsPattern = r'SHB TWCID ....: reportedState .. ActualAmps/MaxAmps (..\...)/'
      lastAmpsUsed = 0
      ampsUsed = 0
      debugOutputCompare = debugOutput
      m1 = re.search(ampsPattern, self.lastHeartbeatDebugOutput)
      if(m1):
        lastAmpsUsed = float(m1.group(1))
      m2 = re.search(ampsPattern, debugOutput)
      if(m2):
        ampsUsed = float(m2.group(1))
        if(m1):
          debugOutputCompare = debugOutputCompare[0:m2.start(1)] + \
              self.lastHeartbeatDebugOutput[m1.start(1):m1.end(1)] + \
              debugOutputCompare[m2.end(1):]
      if(
          debugOutputCompare != self.lastHeartbeatDebugOutput
          or abs(ampsUsed - lastAmpsUsed) >= 1.0
          or time.time() - self.timeLastHeartbeatDebugOutput > 600
          or debugLevel >= 11
      ):
        print(time_now() + debugOutput)
        self.lastHeartbeatDebugOutput = debugOutput
        self.timeLastHeartbeatDebugOutput = time.time()
    except IndexError:
      # This happens if we try to access, say, heartbeatData[8] when
      # len(heartbeatData) < 9. This was happening due to a bug I fixed
      # but I may as well leave this here just in case.
      if(len(heartbeatData) != (7 if self.protocolVersion == 1 else 9)):
        print(time_now() + ': Error in print_status displaying heartbeatData',
              heartbeatData, 'based on msg', hex_str(msg))
      if(len(self.masterHeartbeatData) != (7 if self.protocolVersion == 1 else 9)):
        print(time_now() + ': Error in print_status displaying masterHeartbeatData', self.masterHeartbeatData)

  def send_slave_heartbeat(self, masterID):
    # Send slave heartbeat
    #
    # Heartbeat includes data we store in slaveHeartbeatData.
    # Meaning of data:
    #
    # Byte 1 is a state code:
    #   00 Ready
    #      Car may or may not be plugged in.
    #      When car has reached its charge target, I've repeatedly seen it
    #      change from 03 to 00 the moment I wake the car using the phone app.
    #   01 Plugged in, charging
    #   02 Error
    #      This indicates an error such as not getting a heartbeat message
    #      from Master for too long.
    #   03 Plugged in, do not charge
    #      I've seen this state briefly when plug is first inserted, and
    #      I've seen this state remain indefinitely after pressing stop
    #      charge on car's screen or when the car reaches its target charge
    #      percentage. Unfortunately, this state does not reliably remain
    #      set, so I don't think it can be used to tell when a car is done
    #      charging. It may also remain indefinitely if TWCManager script is
    #      stopped for too long while car is charging even after TWCManager
    #      is restarted. In that case, car will not charge even when start
    #      charge on screen is pressed - only re-plugging in charge cable
    #      fixes it.
    #   04 Plugged in, ready to charge or charge scheduled
    #      I've seen this state even when car is set to charge at a future
    #      time via its UI. In that case, it won't accept power offered to
    #      it.
    #   05 Busy?
    #      I've only seen it hit this state for 1 second at a time and it
    #      can seemingly happen during any other state. Maybe it means wait,
    #      I'm busy? Communicating with car?
    #   08 Starting to charge?
    #      This state may remain for a few seconds while car ramps up from
    #      0A to 1.3A, then state usually changes to 01. Sometimes car skips
    #      08 and goes directly to 01.
    #      I saw 08 consistently each time I stopped fake master script with
    #      car scheduled to charge, plugged in, charge port blue. If the car
    #      is actually charging and you stop TWCManager, after 20-30 seconds
    #      the charge port turns solid red, steering wheel display says
    #      "charge cable fault", and main screen says "check charger power".
    #      When TWCManager is started, it sees this 08 status again. If we
    #      start TWCManager and send the slave a new max power value, 08
    #      becomes 00 and car starts charging again.
    #
    #   Protocol 2 adds a number of other states:
    #   06, 07, 09
    #      These are each sent as a response to Master sending the
    #      corresponding state. Ie if Master sends 06, slave responds with
    #      06. See notes in send_master_heartbeat for meaning.
    #   0A Amp adjustment period complete
    #      Master uses state 06 and 07 to raise or lower the slave by 2A
    #      temporarily.  When that temporary period is over, it changes
    #      state to 0A.
    #   0F was reported by another user but I've not seen it during testing
    #      and have no idea what it means.
    #
    # Byte 2-3 is the max current available as provided by bytes 2-3 in our
    # fake master status.
    # For example, if bytes 2-3 are 0F A0, combine them as 0x0fa0 hex which
    # is 4000 in base 10. Move the decimal point two places left and you get
    # 40.00Amps max.
    #
    # Byte 4-5 represents the power the car is actually drawing for
    # charging. When a car is told to charge at 19A you may see a value like
    # 07 28 which is 0x728 hex or 1832 in base 10. Move the decimal point
    # two places left and you see the charger is using 18.32A.
    # Some TWCs report 0A when a car is not charging while others may report
    # small values such as 0.25A. I suspect 0A is what should be reported
    # and any small value indicates a minor calibration error.
    #
    # Remaining bytes are always 00 00 from what I've seen and could be
    # reserved for future use or may be used in a situation I've not
    # observed.  Protocol 1 uses two zero bytes while protocol 2 uses four.

    ###############################
    # How was the above determined?
    #
    # An unplugged slave sends a status like this:
    #   00 00 00 00 19 00 00
    #
    # A real master always sends all 00 status data to a slave reporting the
    # above status. slaveHeartbeatData[0] is the main driver of how master
    # responds, but whether slaveHeartbeatData[1] and [2] have 00 or non-00
    # values also matters.
    #
    # I did a test with a protocol 1 TWC with fake slave sending
    # slaveHeartbeatData[0] values from 00 to ff along with
    # slaveHeartbeatData[1-2] of 00 and whatever
    # value Master last responded with. I found:
    #   Slave sends:     04 00 00 00 19 00 00
    #   Master responds: 05 12 c0 00 00 00 00
    #
    #   Slave sends:     04 12 c0 00 19 00 00
    #   Master responds: 00 00 00 00 00 00 00
    #
    #   Slave sends:     08 00 00 00 19 00 00
    #   Master responds: 08 12 c0 00 00 00 00
    #
    #   Slave sends:     08 12 c0 00 19 00 00
    #   Master responds: 00 00 00 00 00 00 00
    #
    # In other words, master always sends all 00 unless slave sends
    # slaveHeartbeatData[0] 04 or 08 with slaveHeartbeatData[1-2] both 00.
    #
    # I interpret all this to mean that when slave sends
    # slaveHeartbeatData[1-2] both 00, it's requesting a max power from
    # master. Master responds by telling the slave how much power it can
    # use. Once the slave is saying how much max power it's going to use
    # (slaveHeartbeatData[1-2] = 12 c0 = 32.00A), master indicates that's
    # fine by sending 00 00.
    #
    # However, if the master wants to set a lower limit on the slave, all it
    # has to do is send any heartbeatData[1-2] value greater than 00 00 at
    # any time and slave will respond by setting its
    # slaveHeartbeatData[1-2] to the same value.
    #
    # I thought slave might be able to negotiate a lower value if, say, the
    # car reported 40A was its max capability or if the slave itself could
    # only handle 80A, but the slave dutifully responds with the same value
    # master sends it even if that value is an insane 655.35A. I tested
    # these values on car which has a 40A limit when AC charging and
    # slave accepts them all:
    #   0f aa (40.10A)
    #   1f 40 (80.00A)
    #   1f 41 (80.01A)
    #   ff ff (655.35A)
    global fakeTWCID, slaveHeartbeatData, overrideMasterHeartbeatData

    if(self.protocolVersion == 1 and len(slaveHeartbeatData) > 7):
      # Cut array down to length 7
      slaveHeartbeatData = slaveHeartbeatData[0:7]
    elif(self.protocolVersion == 2):
      while(len(slaveHeartbeatData) < 9):
        # Increase array length to 9
        slaveHeartbeatData.append(0x00)

    send_msg(bytearray(b'\xFD\xE0') + fakeTWCID + bytearray(masterID) + bytearray(slaveHeartbeatData))

  def send_master_heartbeat(self):
    # Send our fake master's heartbeat to this TWCSlave.
    #
    # Heartbeat includes 7 bytes (Protocol 1) or 9 bytes (Protocol 2) of data
    # that we store in masterHeartbeatData.

    # Meaning of data:
    #
    # Byte 1 is a command:
    #   00 Make no changes
    #   02 Error
    #     Byte 2 appears to act as a bitmap where each set bit causes the
    #     slave TWC to enter a different error state. First 8 digits below
    #     show which bits are set and these values were tested on a Protocol
    #     2 TWC:
    #       0000 0001 = Middle LED blinks 3 times red, top LED solid green.
    #                   Manual says this code means 'Incorrect rotary switch
    #                   setting.'
    #       0000 0010 = Middle LED blinks 5 times red, top LED solid green.
    #                   Manual says this code means 'More than three Wall
    #                   Connectors are set to Slave.'
    #       0000 0100 = Middle LED blinks 6 times red, top LED solid green.
    #                   Manual says this code means 'The networked Wall
    #                   Connectors have different maximum current
    #                   capabilities.'
    #   	0000 1000 = No effect
    #   	0001 0000 = No effect
    #   	0010 0000 = No effect
    #   	0100 0000 = No effect
   #       1000 0000 = No effect
    #     When two bits are set, the lowest bit (rightmost bit) seems to
    #     take precedence (ie 111 results in 3 blinks, 110 results in 5
    #     blinks).
    #
    #     If you send 02 to a slave TWC with an error code that triggers
    #     the middle LED to blink red, slave responds with 02 in its
    #     heartbeat, then stops sending heartbeat and refuses further
    #     communication. Slave's error state can be cleared by holding red
    #     reset button on its left side for about 4 seconds.
    #     If you send an error code with bitmap 11110xxx (where x is any bit),
    #     the error can not be cleared with a 4-second reset.  Instead, you
    #     must power cycle the TWC or 'reboot' reset which means holding
    #     reset for about 6 seconds till all the LEDs turn green.
    #   05 Tell slave charger to limit power to number of amps in bytes 2-3.
    #
    # Protocol 2 adds a few more command codes:
    #   06 Increase charge current by 2 amps.  Slave changes its heartbeat
    #      state to 06 in response. After 44 seconds, slave state changes to
    #      0A but amp value doesn't change.  This state seems to be used to
    #      safely creep up the amp value of a slave when the Master has extra
    #      power to distribute.  If a slave is attached to a car that doesn't
    #      want that many amps, Master will see the car isn't accepting the
    #      amps and stop offering more.  It's possible the 0A state change
    #      is not time based but rather indicates something like the car is
    #      now using as many amps as it's going to use.
    #   07 Lower charge current by 2 amps. Slave changes its heartbeat state
    #      to 07 in response. After 10 seconds, slave raises its amp setting
    #      back up by 2A and changes state to 0A.
    #      I could be wrong, but when a real car doesn't want the higher amp
    #      value, I think the TWC doesn't raise by 2A after 10 seconds. Real
    #      Master TWCs seem to send 07 state to all children periodically as
    #      if to check if they're willing to accept lower amp values. If
    #      they do, Master assigns those amps to a different slave using the
    #      06 state.
    #   08 Master acknowledges that slave stopped charging (I think), but
    #      the next two bytes contain an amp value the slave could be using.
    #   09 Tell slave charger to limit power to number of amps in bytes 2-3.
    #      This command replaces the 05 command in Protocol 1. However, 05
    #      continues to be used, but only to set an amp value to be used
    #      before a car starts charging. If 05 is sent after a car is
    #      already charging, it is ignored.
    #
    # Byte 2-3 is the max current a slave TWC can charge at in command codes
    # 05, 08, and 09. In command code 02, byte 2 is a bitmap. With other
    # command codes, bytes 2-3 are ignored.
    # If bytes 2-3 are an amp value of 0F A0, combine them as 0x0fa0 hex
    # which is 4000 in base 10. Move the decimal point two places left and
    # you get 40.00Amps max.
    #
    # Byte 4: 01 when a Master TWC is physically plugged in to a car.
    # Otherwise 00.
    #
    # Remaining bytes are always 00.
    #
    # Example 7-byte data that real masters have sent in Protocol 1:
    #   00 00 00 00 00 00 00  (Idle)
    #   02 04 00 00 00 00 00  (Error bitmap 04.  This happened when I
    #                         advertised a fake Master using an invalid max
    #                         amp value)
    #   05 0f a0 00 00 00 00  (Master telling slave to limit power to 0f a0
    #                         (40.00A))
    #   05 07 d0 01 00 00 00  (Master plugged in to a car and presumably
    #                          telling slaves to limit power to 07 d0
    #                          (20.00A). 01 byte indicates Master is plugged
    #                          in to a car.)
    global fakeTWCID, overrideMasterHeartbeatData, debugLevel, timeLastTx

    if(len(overrideMasterHeartbeatData) >= 7):
      self.masterHeartbeatData = overrideMasterHeartbeatData

    send_msg(bytearray(b'\xFB\xE0') + fakeTWCID + bytearray(self.TWCID)
             + bytearray(self.masterHeartbeatData))


  def receive_slave_heartbeat(self, heartbeatData):
    # Handle heartbeat message received from real slave TWC.
    global debugLevel, nonScheduledAmpsMax, \
           maxAmpsToDivideAmongSlaves, wiringMaxAmpsAllTWCs, \
           slaveTWCRoundRobin, spikeAmpsToCancel6ALimit, \
           chargeNowAmps, chargeNowTimeEnd, minAmpsPerTWC

    now = time.time()
    self.timeLastRx = now

    self.reportedAmpsMax = ((heartbeatData[1] << 8) + heartbeatData[2]) / 100
    self.reportedAmpsActual = ((heartbeatData[3] << 8) + heartbeatData[4]) / 100
    previousState = self.reportedState
    self.reportedState = heartbeatData[0]

    # Leaving state 0 means a car has become active on this charger, and it may
    # not be the one that was here before. Ask for the VIN straight away rather
    # than waiting out the refresh interval, and treat it as unread until the
    # answer arrives so the grace period covers the gap instead of the car
    # being cut to 0A while we wait.
    if(previousState == 0 and self.reportedState != 0):
      if(debugLevel >= 2):
        print(time_now() + ": TWC %02X%02X became active, re-reading its VIN"
          % (self.TWCID[0], self.TWCID[1]))
      self.vinReadDone = False
      self.timeFirstSeen = now
      self.timeLastVINRequest = 0

    # self.lastAmpsOffered is initialized to -1.
    # If we find it at that value, set it to the current value reported by the
    # TWC.
    if(self.lastAmpsOffered < 0):
      self.lastAmpsOffered = self.reportedAmpsMax

    # Keep track of the amps the slave is actually using and the last time it
    # changed by more than 0.8A.
    # Also update self.reportedAmpsActualSignificantChangeMonitor if it's
    # still set to its initial value of -1.
    if(self.reportedAmpsActualSignificantChangeMonitor < 0
       or abs(self.reportedAmpsActual - self.reportedAmpsActualSignificantChangeMonitor) > 0.8
    ):
      self.timeReportedAmpsActualChangedSignificantly = now
      self.reportedAmpsActualSignificantChangeMonitor = self.reportedAmpsActual


    # Ask for the VIN when we don't have one, and refresh it now and then so a
    # car swap is picked up. These TWCs report state 0 even with a car plugged
    # in, so don't gate on state. A refresh returns an empty VIN when the car
    # is gone, which clears it without any separate clearing logic.
    if(self.currentVIN == ""):
      vinInterval = 10 if self.reportedState != 0 else 60
    else:
      vinInterval = 300
    if(now - self.timeLastVINRequest > vinInterval):
      self.timeLastVINRequest = now
      getVehicleVIN(self.TWCID, 0)
      if(debugLevel >= 10):
        print(time_now() + ': Asking TWC %02X%02X for Vehicle VIN (state %d, VIN "%s")' %
          (self.TWCID[0], self.TWCID[1], self.reportedState, self.currentVIN))


    if(chargeNowTimeEnd > 0 and chargeNowTimeEnd < now):
      # We're beyond the one-day period where we want to charge at
      # chargeNowAmps, so reset the chargeNow variables.
      chargeNowAmps = 0
      chargeNowTimeEnd = 0

    if(chargeNowTimeEnd > 0 and chargeNowAmps > 0):
      # We're still in the one-day period where we want to charge at
      # chargeNowAmps, ignoring all other charging criteria.
      maxAmpsToDivideAmongSlaves = chargeNowAmps
      if(debugLevel >= 10):
        print(time_now() + ': Charge at chargeNowAmps %.2f' % (chargeNowAmps))
    else:
      if(nonScheduledAmpsMax > -1):
        maxAmpsToDivideAmongSlaves = nonScheduledAmpsMax

    if(maxAmpsToDivideAmongSlaves > wiringMaxAmpsAllTWCs):
      # Never tell the slaves to draw more amps than the physical charger
      # wiring can handle.
      if(debugLevel >= 1):
        print(time_now() +
            " ERROR: maxAmpsToDivideAmongSlaves " + str(maxAmpsToDivideAmongSlaves) +
            " > wiringMaxAmpsAllTWCs " + str(wiringMaxAmpsAllTWCs) +
            ".\nSee notes above wiringMaxAmpsAllTWCs in the 'Configuration parameters' section.")
      maxAmpsToDivideAmongSlaves = wiringMaxAmpsAllTWCs

    # Determine how many cars are charging and how many amps they're using
    # Count this TWC plus any other TWCs whose car is actually drawing power
    numCarsCharging = 1
    desiredAmpsOffered = maxAmpsToDivideAmongSlaves
    for slaveTWC in slaveTWCRoundRobin:
      if(slaveTWC.TWCID != self.TWCID):
        # To avoid exceeding maxAmpsToDivideAmongSlaves, we must
        # subtract the actual amps being used by this TWC from the amps
        # we will offer.
        desiredAmpsOffered -= slaveTWC.reportedAmpsActual
        if(slaveTWC.reportedAmpsActual >= 1.0):
          numCarsCharging += 1

    # Allocate this slave a fraction of maxAmpsToDivideAmongSlaves divided
    # by the number of cars actually charging.
    fairShareAmps = int(maxAmpsToDivideAmongSlaves / numCarsCharging)
    if(desiredAmpsOffered > fairShareAmps):
      desiredAmpsOffered = fairShareAmps

    # Only report if there is a change
    if(debugLevel >= 10 and maxAmpsToDivideAmongSlaves != desiredAmpsOffered):
      print("desiredAmpsOffered for TWC %02X%02X reduced from %.2f to %.2f, "
            "shared with %d car(s) drawing power, this TWC included."
        % (self.TWCID[0], self.TWCID[1], maxAmpsToDivideAmongSlaves,
           desiredAmpsOffered, numCarsCharging))

    minAmpsToOffer = minAmpsPerTWC
    if(self.minAmpsTWCSupports > minAmpsToOffer):
      minAmpsToOffer = self.minAmpsTWCSupports

    if(desiredAmpsOffered < minAmpsToOffer):
      if(maxAmpsToDivideAmongSlaves / numCarsCharging > minAmpsToOffer):
        # There is enough power available to give each car
        # minAmpsToOffer, but currently-charging cars are leaving us
        # less power than minAmpsToOffer to give this car.
        #
        # minAmpsToOffer is based on minAmpsPerTWC which is
        # user-configurable, whereas self.minAmpsTWCSupports is based on
        # the minimum amps TWC must be set to reliably start a car
        # charging.
        #
        # Unfortunately, we can't tell if a car is plugged in or wanting
        # to charge without offering it minAmpsTWCSupports. As the car
        # gradually starts to charge, we will see it using power and
        # tell other TWCs on the network to use less power. This could
        # cause the sum of power used by all TWCs to exceed
        # wiringMaxAmpsAllTWCs for a few seconds, but I don't think
        # exceeding by up to minAmpsTWCSupports for such a short period
        # of time will cause problems.
        if(debugLevel >= 10):
          print("desiredAmpsOffered increased from %.2f to %.2f (self.minAmpsTWCSupports)"
            % (desiredAmpsOffered, self.minAmpsTWCSupports))
        desiredAmpsOffered = self.minAmpsTWCSupports
      else:
        # There is not enough power available to give each car
        # minAmpsToOffer, so don't offer power to any cars. Alternately,
        # we could charge one car at a time and switch cars
        # periodically, but I'm not going to try to implement that.
        #
        # Note that 5A is the lowest value you can set using the Tesla car's
        # main screen, so lower values might have some adverse affect on the
        # car. I actually tried lower values when the sun was providing
        # under 5A of power and found the car would occasionally set itself
        # to state 03 and refuse to charge until you re-plugged the charger
        # cable. Clicking "Start charging" in the car's UI or in the phone
        # app would not start charging.
        #
        # A 5A charge only delivers ~3 miles of range to the car per hour,
        # but it forces the car to remain "on" at a level that it wastes
        # some power while it's charging. The lower the amps, the more power
        # is wasted. This is another reason not to go below 5A.
        #
        # So if there isn't at least 5A of power available, pass 0A as the
        # desired value. This tells the car to stop charging and it will
        # enter state 03 and go to sleep. You will hear the power relay in
        # the TWC turn off. When desiredAmpsOffered trends above 6A again,
        # it tells the car there's power.
        # If a car is set to energy saver mode in the car's UI, the car
        # seems to wake every 15 mins or so (unlocking or using phone app
        # also wakes it) and next time it wakes, it will see there's power
        # and start charging. Without energy saver mode, the car should
        # begin charging within about 10 seconds of changing this value.
        if(debugLevel >= 10):
          print("desiredAmpsOffered reduced to 0 from " + str(desiredAmpsOffered)
                + " because maxAmpsToDivideAmongSlaves "
                + str(maxAmpsToDivideAmongSlaves)
                + " / numCarsCharging " + str(numCarsCharging)
                + " < minAmpsToOffer " + str(minAmpsToOffer))
        desiredAmpsOffered = 0

      if(
             self.lastAmpsOffered > 0
               and
             (
               now - self.timeLastAmpsOfferedChanged < 60
                 or
               now - self.timeReportedAmpsActualChangedSignificantly < 60
                 or
               self.reportedAmpsActual < 4.0
             )
          ):
        # We were previously telling the car to charge but now we want
        # to tell it to stop. However, it's been less than a minute
        # since we told it to charge or since the last significant
        # change in the car's actual power draw or the car has not yet
        # started to draw at least 5 amps (telling it 5A makes it
        # actually draw around 4.18-4.27A so we check for
        # self.reportedAmpsActual < 4.0).
        #
        # Once we tell the car to charge, we want to keep it going for
        # at least a minute before turning it off again. concern is that
        # yanking the power at just the wrong time during the
        # start-charge negotiation could put the car into an error state
        # where it won't charge again without being re-plugged. This
        # concern is hypothetical and most likely could not happen to a
        # real car, but I'd rather not take any chances with getting
        # someone's car into a non-charging state so they're stranded
        # when they need to get somewhere. Note that non-Tesla cars
        # using third-party adapters to plug in are at a higher risk of
        # encountering this sort of hypothetical problem.
        #
        # The other reason for this tactic is that in the minute we
        # wait, desiredAmpsOffered might rise above 5A in which case we
        # won't have to turn off the charger power at all. Avoiding too
        # many on/off cycles preserves the life of the TWC's main power
        # relay and may also prevent errors in the car that might be
        # caused by turning its charging on and off too rapidly.
        #
        # Seeing self.reportedAmpsActual < 4.0 means the car hasn't
        # ramped up to whatever level we told it to charge at last time.
        # It may be asleep and take up to 15 minutes to wake up, see
        # there's power, and start charging.
        #
        # Unfortunately, self.reportedAmpsActual < 4.0 can also mean the
        # car is at its target charge level and may not accept power for
        # days until the battery drops below a certain level. I can't
        # think of a reliable way to detect this case. When the car
        # stops itself from charging, we'll see self.reportedAmpsActual
        # drop to near 0.0A and heartbeatData[0] becomes 03, but we can
        # see the same 03 state when we tell the TWC to stop charging.
        # We could record the time the car stopped taking power and
        # assume it won't want more for some period of time, but we
        # can't reliably detect if someone unplugged the car, drove it,
        # and re-plugged it so it now needs power, or if someone plugged
        # in a different car that needs power. Even if I see the car
        # hasn't taken the power we've offered for the
        # last hour, it's conceivable the car will reach a battery state
        # where it decides it wants power the moment we decide it's safe
        # to stop offering it. Thus, I think it's safest to always wait
        # until the car has taken 5A for a minute before cutting power
        # even if that means the car will charge for a minute when you
        # first plug it in after a trip even at a time when no power
        # should be available.
        #
        # One advantage of the above situation is that whenever you plug
        # the car in, unless no power has been available since you
        # unplugged, the charge port will turn green and start charging
        # for a minute. This lets the owner quickly see that TWCManager
        # is working properly each time they return home and plug in.
        if(debugLevel >= 10):
          print("Don't stop charging yet because: " +
                'time - self.timeLastAmpsOfferedChanged ' +
                str(int(now - self.timeLastAmpsOfferedChanged)) +
                ' < 60 or time - self.timeReportedAmpsActualChangedSignificantly ' +
                str(int(now - self.timeReportedAmpsActualChangedSignificantly)) +
                ' < 60 or self.reportedAmpsActual ' + str(self.reportedAmpsActual) +
                ' < 4')
        desiredAmpsOffered = minAmpsToOffer
    else:
      # We can tell the TWC how much power to use in 0.01A increments, but
      # the car will only alter its power in larger increments (somewhere
      # between 0.5 and 0.6A). The car seems to prefer being sent whole
      # amps and when asked to adjust between certain values like 12.6A
      # one second and 12.0A the next second, the car reduces its power
      # use to ~5.14-5.23A and refuses to go higher. So it seems best to
      # stick with whole amps.
      desiredAmpsOffered = int(desiredAmpsOffered)

      if(self.lastAmpsOffered == 0
         and now - self.timeLastAmpsOfferedChanged < 60
      ):
        # Keep charger off for at least 60 seconds before turning back
        # on. See reasoning above where I don't turn the charger off
        # till it's been on at least 60 seconds.
        if(debugLevel >= 10):
          print("Don't start charging yet because: " +
                'self.lastAmpsOffered ' +
                str(self.lastAmpsOffered) + " == 0 " +
                'and time - self.timeLastAmpsOfferedChanged ' +
                str(int(now - self.timeLastAmpsOfferedChanged)) +
                " < 60")
        desiredAmpsOffered = self.lastAmpsOffered
      else:
        # Mid Oct 2017, Tesla pushed a firmware update to their cars
        # that seems to create the following bug:
        # If you raise desiredAmpsOffered AT ALL from the car's current
        # max amp limit, the car will drop its max amp limit to the 6A
        # setting (5.14-5.23A actual use as reported in
        # heartbeatData[2-3]). The odd fix to this problem is to tell
        # the car to raise to at least spikeAmpsToCancel6ALimit for 5 or
        # more seconds, then tell it to lower the limit to
        # desiredAmpsOffered. Even 0.01A less than
        # spikeAmpsToCancel6ALimit is not enough to cancel the 6A limit.
        #
        # I'm not sure how long we have to hold spikeAmpsToCancel6ALimit
        # but 3 seconds is definitely not enough but 5 seconds seems to
        # work. It doesn't seem to matter if the car actually hits
        # spikeAmpsToCancel6ALimit of power draw. In fact, the car is
        # slow enough to respond that even with 10s at 21A the most I've
        # seen it actually draw starting at 6A is 13A.
        if(debugLevel >= 10):
          print('desiredAmpsOffered=' + str(desiredAmpsOffered) +
                ' spikeAmpsToCancel6ALimit=' + str(spikeAmpsToCancel6ALimit) +
                ' self.lastAmpsOffered=' + str(self.lastAmpsOffered) +
                ' self.reportedAmpsActual=' + str(self.reportedAmpsActual) +
                ' now - self.timeReportedAmpsActualChangedSignificantly=' +
                str(int(now - self.timeReportedAmpsActualChangedSignificantly)))

        if(
            # If we just moved from a lower amp limit to
            # a higher one less than spikeAmpsToCancel6ALimit.
           (
             desiredAmpsOffered < spikeAmpsToCancel6ALimit
               and
             desiredAmpsOffered > self.lastAmpsOffered
           )
              or
           (
             # ...or if we've been offering the car more amps than it's
             # been using for at least 10 seconds, then we'll change the
             # amps we're offering it. For some reason, the change in
             # amps offered will get the car to up its amp draw.
             #
             # First, check that the car is drawing enough amps to be
             # charging...
             self.reportedAmpsActual > 2.0
               and
             # ...and car is charging at under spikeAmpsToCancel6ALimit.
             # I think I've seen cars get stuck between spikeAmpsToCancel6ALimit
             # and lastAmpsOffered, but more often a car will be limited
             # to under lastAmpsOffered by its UI setting or by the
             # charger hardware it has on board, and we don't want to
             # keep reducing it to spikeAmpsToCancel6ALimit.
             # If cars really are getting stuck above
             # spikeAmpsToCancel6ALimit, I may need to implement a
             # counter that tries spikeAmpsToCancel6ALimit only a
             # certain number of times per hour.
             (self.reportedAmpsActual <= spikeAmpsToCancel6ALimit)
               and
             # ...and car is charging at over two amps under what we
             # want it to charge at. I have to use 2 amps because when
             # offered, say 40A, the car charges at ~38.76A actual.
             # Using a percentage instead of 2.0A doesn't work because
             # 38.58/40 = 95.4% but 5.14/6 = 85.6%
             (self.lastAmpsOffered - self.reportedAmpsActual) > 2.0
               and
             # ...and car hasn't changed its amp draw significantly in
             # over 10 seconds, meaning it's stuck at its current amp
             # draw.
             now - self.timeReportedAmpsActualChangedSignificantly > 10
           )
        ):
          # We must set desiredAmpsOffered to a value that gets
          # reportedAmpsActual (amps the car is actually using) up to
          # a value near lastAmpsOffered. At the end of all these
          # checks, we'll set lastAmpsOffered = desiredAmpsOffered and
          # timeLastAmpsOfferedChanged if the value of lastAmpsOffered was
          # actually changed.
          if(self.lastAmpsOffered == spikeAmpsToCancel6ALimit
             and now - self.timeLastAmpsOfferedChanged > 10):
            # We've been offering the car spikeAmpsToCancel6ALimit
            # for over 10 seconds but it's still drawing at least
            # 2A less than spikeAmpsToCancel6ALimit.  I saw this
            # happen once when an error stopped the car from
            # charging and when the error cleared, it was offered
            # spikeAmpsToCancel6ALimit as the first value it saw.
            # The car limited itself to 6A indefinitely. In this
            # case, the fix is to offer it lower amps.
            if(debugLevel >= 1):
              print(time_now() + ': Car stuck when offered spikeAmpsToCancel6ALimit.  Offering 2 less.')
            desiredAmpsOffered = spikeAmpsToCancel6ALimit - 2.0
          elif(now - self.timeLastAmpsOfferedChanged > 5):
            # self.lastAmpsOffered hasn't gotten the car to draw
            # enough amps for over 5 seconds, so try
            # spikeAmpsToCancel6ALimit
            desiredAmpsOffered = spikeAmpsToCancel6ALimit
          else:
            # Otherwise, don't change the value of lastAmpsOffered.
            desiredAmpsOffered = self.lastAmpsOffered

        # Note that the car should have no problem increasing max
        # amps to any whole value over spikeAmpsToCancel6ALimit as
        # long as it's below any upper limit manually set in the
        # car's UI. One time when I couldn't get TWC to push the car
        # over 21A, I found the car's UI had set itself to 21A
        # despite setting it to 40A the day before. I have been
        # unable to reproduce whatever caused that problem.
        elif(desiredAmpsOffered < self.lastAmpsOffered):
          # Tesla doesn't mind if we set a lower amp limit than the
          # one we're currently using, but make sure we don't change
          # limits more often than every 5 seconds. This has the side
          # effect of holding spikeAmpsToCancel6ALimit set earlier for
          # 5 seconds to make sure the car sees it.
          if(debugLevel >= 10):
            print('Reduce amps: time - self.timeLastAmpsOfferedChanged ' +
                str(int(now - self.timeLastAmpsOfferedChanged)))
          if(now - self.timeLastAmpsOfferedChanged < 5):
            desiredAmpsOffered = self.lastAmpsOffered

    # VIN approval check. Do this last so it overrides every other decision.
    #
    # Only enforced while the TWC reports a state other than 0. At state 0 no
    # current can flow, and a car that has gone to sleep while plugged in looks
    # exactly like an empty charger on this protocol, so blocking there gains
    # nothing and would cut an approved car that is merely asleep.
    #
    # It is also held off until this TWC has had its say: either a VIN read has
    # finished, or it has had VIN_GRACE_SECONDS to produce one. Without that,
    # a restart, or a car waking up, is cut to 0A before its VIN arrives, and
    # the 60 second restart guard then keeps it off for a full minute.
    if(self.reportedState != 0
       and (self.vinReadDone or now - self.timeFirstSeen > VIN_GRACE_SECONDS)
       and not vin_approved(self.currentVIN)):
      # This runs on every heartbeat, so only say so when the VIN changes or
      # once a minute. Otherwise a blocked car fills the log at 1 line/2s.
      if(debugLevel >= 1 and desiredAmpsOffered > 0
         and (self.currentVIN != self.lastVINRefused
              or now - self.timeLastVINRefusedPrint > 60)):
        self.lastVINRefused = self.currentVIN
        self.timeLastVINRefusedPrint = now
        print(time_now() + ': TWC %02X%02X: VIN "%s" not approved, offering 0A' %
          (self.TWCID[0], self.TWCID[1], self.currentVIN))
      desiredAmpsOffered = 0

    # set_last_amps_offered does some final checks to see if the new
    # desiredAmpsOffered is safe. It should be called after we've picked a
    # final value for desiredAmpsOffered.
    desiredAmpsOffered = self.set_last_amps_offered(desiredAmpsOffered)

    # See notes in send_slave_heartbeat() for details on how we transmit
    # desiredAmpsOffered and the meaning of the code in
    # self.masterHeartbeatData[0].
    #
    # Rather than only sending desiredAmpsOffered when slave is sending code
    # 04 or 08, it seems to work better to send desiredAmpsOffered whenever
    # it does not equal self.reportedAmpsMax reported by the slave TWC.
    # Doing it that way will get a slave charging again even when it's in
    # state 00 or 03 which it swings between after you set
    # desiredAmpsOffered = 0 to stop charging.
    #
    # I later found that a slave may end up swinging between state 01 and 03
    # when desiredAmpsOffered == 0:
    #   S 032e 0.25/0.00A: 01 0000 0019 0000  M: 00 0000 0000 0000
    #   S 032e 0.25/6.00A: 03 0258 0019 0000  M: 05 0000 0000 0000
    #   S 032e 0.25/0.00A: 01 0000 0019 0000  M: 00 0000 0000 0000
    #   S 032e 0.25/6.00A: 03 0258 0019 0000  M: 05 0000 0000 0000
    #
    # While it's doing this, it's continuously opening and closing the relay
    # on the TWC each second which makes an audible click and will wear out
    # the relay. To avoid that problem, always send code 05 when
    # desiredAmpsOffered == 0. In that case, slave's response should always
    # look like this:
    #   S 032e 0.25/0.00A: 03 0000 0019 0000 M: 05 0000 0000 0000
    if(self.reportedAmpsMax != desiredAmpsOffered
       or desiredAmpsOffered == 0
    ):
      desiredHundredthsOfAmps = int(desiredAmpsOffered * 100)
      self.masterHeartbeatData = bytearray([(0x09 if self.protocolVersion == 2 else 0x05),
        (desiredHundredthsOfAmps >> 8) & 0xFF,
        desiredHundredthsOfAmps & 0xFF,
        0x00,0x00,0x00,0x00,0x00,0x00])
    else:
      self.masterHeartbeatData = bytearray([0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00])

    if(len(overrideMasterHeartbeatData) >= 7):
      self.masterHeartbeatData = overrideMasterHeartbeatData

    if(debugLevel >= 1):
      self.print_status(heartbeatData)


  def set_last_amps_offered(self, desiredAmpsOffered):
    # self.lastAmpsOffered should only be changed using this sub.
    global debugLevel

    if(debugLevel >= 10):
      print("set_last_amps_offered(TWCID=" + hex_str(self.TWCID) +
            ", desiredAmpsOffered=" + str(desiredAmpsOffered) + ")")

    if(desiredAmpsOffered != self.lastAmpsOffered):
      oldLastAmpsOffered = self.lastAmpsOffered
      self.lastAmpsOffered = desiredAmpsOffered

      # Set totalAmpsAllTWCs to the total amps all TWCs are actually using
      # minus amps this TWC is using, plus amps this TWC wants to use.
      totalAmpsAllTWCs = total_amps_actual_all_twcs() \
            - self.reportedAmpsActual + self.lastAmpsOffered
      if(totalAmpsAllTWCs > wiringMaxAmpsAllTWCs):
        # totalAmpsAllTWCs would exceed wiringMaxAmpsAllTWCs if we
        # allowed this TWC to use desiredAmpsOffered.  Instead, try
        # offering as many amps as will increase total_amps_actual_all_twcs()
        # up to wiringMaxAmpsAllTWCs.
        self.lastAmpsOffered = int(wiringMaxAmpsAllTWCs -
                                  (total_amps_actual_all_twcs() - self.reportedAmpsActual))

        if(self.lastAmpsOffered < self.minAmpsTWCSupports):
          # Always offer at least minAmpsTWCSupports amps.
          # See notes in receive_slave_heartbeat() beneath
          # 'if(maxAmpsToDivideAmongSlaves / numCarsCharging > minAmpsToOffer):'
          self.lastAmpsOffered = self.minAmpsTWCSupports

        # Only worth saying when the clamp actually changed the offer
        if(self.lastAmpsOffered != desiredAmpsOffered):
          print("WARNING: Offering slave TWC %02X%02X %.1fA instead of " \
              "%.1fA to avoid overloading wiring shared by all TWCs." % (
              self.TWCID[0], self.TWCID[1], self.lastAmpsOffered, desiredAmpsOffered))

      if(self.lastAmpsOffered > self.wiringMaxAmps):
        # We reach this case frequently in some configurations, such as
        # when two 80A TWCs share a 125A line.  Therefore, don't print
        # an error.
        self.lastAmpsOffered = self.wiringMaxAmps
        if(debugLevel >= 10):
          print("Offering slave TWC %02X%02X %.1fA instead of " \
              "%.1fA to avoid overloading the TWC rated at %.1fA." % (
              self.TWCID[0], self.TWCID[1], self.lastAmpsOffered,
              desiredAmpsOffered, self.wiringMaxAmps))

      if(self.lastAmpsOffered != oldLastAmpsOffered):
        self.timeLastAmpsOfferedChanged = time.time()
    return self.lastAmpsOffered

#
# End TWCSlave class
#
##############################




##############################
#
# Begin main program
#
def main():
  global debugLevel, ser, configFileName, statusFileName
  global slaveTWCs, slaveTWCRoundRobin, slaveHeartbeatData
  global timeLastTx, overrideMasterHeartbeatData, maxAmpsToDivideAmongSlaves, chargeNowAmps, chargeNowTimeEnd, spikeAmpsToCancel6ALimit
  global kWhDelivered, nonScheduledAmpsMax, approvedVINs
  global fakeTWCID, masterTWCID

  data = ''
  dataLen = 0

  ignoredData = bytearray()
  msg = bytearray()
  msgLen = 0
  msgRxCount = 0

  numInitMsgsToSend = 10

  lastTWCResponseMsg = None
  idxSlaveToSendNextHeartbeat = 0

  timeLastkWhDelivered = time.time()
  timeLastkWhSaved = time.time()
  timeReport = time.time()

  timeTo0Aafter06 = 0
  timeToRaise2A = 0

  print("Started %s - %s" % (progname, version))

  (configFile, logLevel) = parse_arguments()
  if(configFile is not None):
    configFileName = configFile
  configFileName = resolve_path(configFileName)

  load_config()

  # A -l on the command line wins over debugLevel in the settings file
  if(logLevel is not None):
    debugLevel = logLevel

  print("Debuglevel is", debugLevel)

  load_status()

  ser = serial.Serial(rs485Adapter, baud, timeout=0)

  # Create an IPC (Interprocess Communication) message queue that we can
  # periodically check to respond to queries from the TWCManager web interface.
  #
  # These messages will contain commands like "start charging at 10A" or may ask
  # for information like "how many amps is the solar array putting out".
  #
  # The message queue is identified by a numeric key. This script and the web
  # interface must both use the same key. The "ftok" function facilitates creating
  # such a key based on a shared piece of information that is not likely to
  # conflict with keys chosen by any other process in the system.
  #
  # ftok reads the inode number of the file or directory pointed to by its first
  # parameter. This file or dir must already exist and the permissions on it don't
  # seem to matter. The inode of a particular file or dir is fairly unique but
  # doesn't change often so it makes a decent choice for a key.  We use the parent
  # directory of the TWCManager script.
  #
  # The second parameter to ftok is a single byte that adds some additional
  # uniqueness and lets you create multiple queues linked to the file or dir in
  # the first param. We use 'T' for Tesla.
  #
  # If you can't get this to work, you can also set key = <some arbitrary number>
  # and in the web interface, use the same arbitrary number. While that could
  # conflict with another process, it's very unlikely to.
  #webIPCkey = sysv_ipc.ftok(re.sub('/[^/]+$', '/', __file__), ord('T'), True)
  # EZ changed to force the folder
  webIPCkey = sysv_ipc.ftok(webIPCDir, ord('T'), True)
  print("WebIPC key is", webIPCkey)

  # Use the key to create a message queue with read/write access for all users.
  webIPCqueue = sysv_ipc.MessageQueue(webIPCkey, sysv_ipc.IPC_CREAT, 0o666)
  if(webIPCqueue == None):
    print("ERROR: Can't create Interprocess Communication message queue to communicate with web interface.")

  # After the IPC message queue is created, if you type 'sudo ipcs -q' on the
  # command like, you should see something like:
  # ------ Message Queues --------
  # key        msqid      owner      perms      used-bytes   messages
  # 0x5402ed16 491520     pi         666        0            0
  #
  # Notice that we've created the only IPC message queue in the system. Apparently
  # default software on the pi doesn't use IPC or if it does, it creates and
  # deletes its message queues quickly.
  #
  # If you want to get rid of all queues because you created extras accidentally,
  # reboot or type 'sudo ipcrm -a msg'.  Don't get rid of all queues if you see
  # ones you didn't create or you may crash another process.
  # Find more details in IPC here:
  # http://www.onlamp.com/pub/a/php/2004/05/13/shared_memory.html

  try:
    db = mysql.connector.connect(user=mysql_user, password=mysql_passwd, host=mysql_host, database=mysql_database)
    cursor = db.cursor()
    print("Opened MySQL Database successfully")
  except Exception as e:
    print("Can't open the database: %s" % str(e))
    exit(-1)


  print("TWC Manager starting as fake %s with id %02X%02X and sign %02X" \
      % ( ("Master" if fakeMaster else "Slave"), \
      ord(fakeTWCID[0:1]), ord(fakeTWCID[1:2]), ord(slaveSign)))

  while True:
    try:
      # In this area, we always send a linkready message when we first start.
      # Whenever there is no data available from other TWCs to respond to,
      # we'll loop back to this point to send another linkready or heartbeat
      # message. By only sending our periodic messages when no incoming
      # message data is available, we reduce the chance that we will start
      # transmitting a message in the middle of an incoming message, which
      # would corrupt both messages.

      # Add a 25ms sleep to prevent pegging pi's CPU at 100%. Lower CPU means
      # less power used and less waste heat.
      time.sleep(0.025)

      now = time.time()

      if(fakeMaster == 1):
        # A real master sends 5 copies of linkready1 and linkready2 whenever
        # it starts up, which we do here.
        # It doesn't seem to matter if we send these once per second or once
        # per 100ms so I do once per 100ms to get them over with.
        if(numInitMsgsToSend > 5):
          send_master_linkready1()
          time.sleep(0.1) # give slave time to respond
          numInitMsgsToSend -= 1
        elif(numInitMsgsToSend > 0):
          send_master_linkready2()
          time.sleep(0.1) # give slave time to respond
          numInitMsgsToSend = numInitMsgsToSend - 1
        else:
          # After finishing the 5 startup linkready1 and linkready2
          # messages, master will send a heartbeat message to every slave
          # it's received a linkready message from. Do that here.
          # A real master would keep sending linkready messages periodically
          # as long as no slave was connected, but since real slaves send
          # linkready once every 10 seconds till they're connected to a
          # master, we'll just wait for that.
          if(time.time() - timeLastTx >= 1.0):
            # It's been about a second since our last heartbeat.
            if(len(slaveTWCRoundRobin) > 0):
              slaveTWC = slaveTWCRoundRobin[idxSlaveToSendNextHeartbeat]
              if(time.time() - slaveTWC.timeLastRx > 26):
                # A real master stops sending heartbeats to a slave
                # that hasn't responded for ~26 seconds. It may
                # still send the slave a heartbeat every once in
                # awhile but we're just going to scratch the slave
                # from our little black book and add them again if
                # they ever send us a linkready.
                print(time_now() + ": WARNING: We haven't heard from slave " \
                    "%02X%02X for over 26 seconds.  " \
                    "Stop sending them heartbeat messages." % \
                    (slaveTWC.TWCID[0], slaveTWC.TWCID[1]))
                delete_slave(slaveTWC.TWCID)
              else:
                slaveTWC.send_master_heartbeat()

              idxSlaveToSendNextHeartbeat = idxSlaveToSendNextHeartbeat + 1
              if(idxSlaveToSendNextHeartbeat >= len(slaveTWCRoundRobin)):
                idxSlaveToSendNextHeartbeat = 0
              time.sleep(0.1) # give slave time to respond
      else: # fakemaster<>1
        # As long as a slave is running, it sends link ready messages every
        # 10 seconds. They trigger any master on the network to handshake
        # with the slave and the master then sends a status update from the
        # slave every 1-3 seconds. Master's status updates trigger the slave
        # to send back its own status update.
        # As long as master has sent a status update within the last 10
        # seconds, slaves don't send link ready.
        # I've also verified that masters don't care if we stop sending link
        # ready as long as we send status updates in response to master's
        # status updates.
        if(fakeMaster != 2 and time.time() - timeLastTx >= 10.0):
          if(debugLevel >= 1):
            print("Advertise fake slave %02X%02X with sign %02X is " \
                  "ready to link once per 10 seconds as long as master " \
                  "hasn't sent a heartbeat in the last 10 seconds." % \
                (ord(fakeTWCID[0:1]), ord(fakeTWCID[1:2]), ord(slaveSign)))
          send_slave_linkready()


      ########################################################################
      # See if there's any message from the web interface.
      # If the message is longer than msgMaxSize, MSG_NOERROR tells it to
      # return what it can of the message and discard the rest.
      # When no message is available, IPC_NOWAIT tells msgrcv to return
      # msgResult = 0 and $! = 42 with description 'No message of desired
      # type'.
      try:
        webMsgRaw = webIPCqueue.receive(False, 2)
        if(len(webMsgRaw[0]) > 0):
          webMsgType = webMsgRaw[1]
          unpacked = struct.unpack('=LH', webMsgRaw[0][0:6])
          webMsgTime = unpacked[0]
          webMsgID = unpacked[1]
          webMsg = webMsgRaw[0][6:len(webMsgRaw[0])]

          if(debugLevel >= 1):
            webMsgRedacted = webMsg
            print(time_now() + ": Web query: '" + str(webMsgRedacted) + "', id " + str(webMsgID) +
                               ", time " + str(webMsgTime) + ", type " + str(webMsgType))
          webResponseMsg = ''
          numPackets = 0
          if(webMsg == b'getStatus'):
            webResponseMsg = (
                      "%.2f" % (maxAmpsToDivideAmongSlaves) +
                '`' + "%.2f" % (wiringMaxAmpsAllTWCs) +
                '`' + "%.2f" % (minAmpsPerTWC) +
                '`' + "%.2f" % (chargeNowAmps) +
                '`' + str(nonScheduledAmpsMax) +
                '`' + str(len(slaveTWCRoundRobin))
                )

            for i in range(0, len(slaveTWCRoundRobin)):
              webResponseMsg += (
                  '`' + "%02X%02X" % (slaveTWCRoundRobin[i].TWCID[0],
                                                    slaveTWCRoundRobin[i].TWCID[1]) +
                  '~' + str(slaveTWCRoundRobin[i].maxAmps) +
                  '~' + "%.2f" % (slaveTWCRoundRobin[i].reportedAmpsActual) +
                  '~' + str(slaveTWCRoundRobin[i].lastAmpsOffered) +
                  '~' + str(slaveTWCRoundRobin[i].reportedState) +
                  '~' + slaveTWCRoundRobin[i].currentVIN
                  )

          elif(webMsg[0:20] == b'setNonScheduledAmps='):
            m = re.search(b'([-0-9]+)', webMsg[19:len(webMsg)])
            if(m):
              nonScheduledAmpsMax = int(m.group(1))

              # Save nonScheduledAmpsMax so the setting isn't lost
              # on power failure or script restart
              save_status()
          elif(webMsg[0:11] == b'sendTWCMsg='):
            m = re.search(b'([0-9a-fA-F]+)', webMsg[11:len(webMsg)], re.MULTILINE)
            if(m):
              twcMsg = trim_pad(bytearray.fromhex(m.group(1).decode('ascii')),
                                15 if len(slaveTWCRoundRobin) == 0 \
                                or slaveTWCRoundRobin[0].protocolVersion == 2 else 13)
              if((twcMsg[0:2] == b'\xFC\x19') or (twcMsg[0:2] == b'\xFC\x1A')):
                print("\n*** ERROR: Web interface requested sending command:\n"
                      + hex_str(twcMsg)
                      + "\nwhich could permanently disable the TWC.  Aborting.\n")
              elif((twcMsg[0:2] == b'\xFB\xE8')):
                print("\n*** ERROR: Web interface requested sending command:\n"
                      + hex_str(twcMsg)
                      + "\nwhich could crash the TWC.  Aborting.\n")
              else:
                lastTWCResponseMsg = bytearray();
                send_msg(twcMsg)
          elif(webMsg == b'getLastTWCMsgResponse'):
            if(lastTWCResponseMsg != None and lastTWCResponseMsg != b''):
              webResponseMsg = hex_str(lastTWCResponseMsg)
            else:
              webResponseMsg = 'None'
          elif(webMsg[0:23] == b'setMasterHeartbeatData='):
            m = re.search(b'([0-9a-fA-F]*)', webMsg[23:len(webMsg)], re.MULTILINE)
            if(m):
              if(len(m.group(1)) > 0):
                overrideMasterHeartbeatData = trim_pad(bytearray.fromhex(m.group(1).decode('ascii')),
                                                       9 if slaveTWCRoundRobin[0].protocolVersion == 2 else 7)
              else:
                overrideMasterHeartbeatData = b''
          elif(webMsg == b'chargeNow'):
            chargeNowAmps = wiringMaxAmpsAllTWCs
            chargeNowTimeEnd = now + 60*60*24
          elif(webMsg == b'chargeNowCancel'):
            chargeNowAmps = 0
            chargeNowTimeEnd = 0
          elif(webMsg == b'dumpState'):
            # dumpState commands are used for debugging. They are called
            # using a web page:
            # http://(Pi address)/index.php?submit=1&dumpState=1
            webResponseMsg = ('time=' + str(now) + ', fakeMaster='
                + str(fakeMaster) + ', rs485Adapter=' + rs485Adapter
                + ', baud=' + str(baud)
                + ', wiringMaxAmpsAllTWCs=' + str(wiringMaxAmpsAllTWCs)
                + ', wiringMaxAmpsPerTWC=' + str(wiringMaxAmpsPerTWC)
                + ', minAmpsPerTWC=' + str(minAmpsPerTWC)
                + ', debugLevel=' + str(debugLevel)
                + ', configFileName=' + str(configFileName)
                + ', statusFileName=' + str(statusFileName)
                + ', blockUnknownVINs=' + str(blockUnknownVINs)
                + '\n')

            webResponseMsg += 'slaveTWCRoundRobin:\n'
            for slaveTWC in slaveTWCRoundRobin:
              webResponseMsg += str(slaveTWC.__dict__) + '\n'

            numPackets = math.ceil(len(webResponseMsg) / 290)
          elif(webMsg[0:14] == b'setDebugLevel='):
            m = re.search(b'([-0-9]+)', webMsg[14:len(webMsg)], re.MULTILINE)
            if(m):
              debugLevel = int(m.group(1))
          elif(webMsg == b'getVINs'):
            now2 = time.time()
            parts = []
            for i in range(0, len(slaveTWCRoundRobin)):
              vin = slaveTWCRoundRobin[i].currentVIN
              expiry = approvedVINs.get(vin, -1) if vin != "" else -1
              parts.append(
                  "%02X%02X" % (slaveTWCRoundRobin[i].TWCID[0],
                                slaveTWCRoundRobin[i].TWCID[1]) +
                  '~' + vin +
                  '~' + str(int(expiry)))
            webResponseMsg = '`'.join(parts)
          elif(webMsg[0:11] == b'approveVIN='):
            m = re.search(b'([0-9A-Za-z]{17}),([-0-9]+)', webMsg[11:len(webMsg)])
            if(m):
              vin = m.group(1).decode('ascii')
              hours = int(m.group(2))
              approvedVINs[vin] = 0 if hours == 0 else int(time.time()) + hours*3600
              save_status()
              print(time_now() + ": Approved VIN %s for %s" %
                    (vin, "ever" if hours == 0 else str(hours) + "h"))
          elif(webMsg[0:10] == b'revokeVIN='):
            m = re.search(b'([0-9A-Za-z]{17})', webMsg[10:len(webMsg)])
            if(m):
              vin = m.group(1).decode('ascii')
              approvedVINs.pop(vin, None)
              save_status()
              print(time_now() + ": Revoked VIN %s" % vin)
          else:
            print(time_now() + ": Unknown IPC request from web server: " + str(webMsg))

          if(len(webResponseMsg) > 0):
            if(debugLevel >= 5):
              print(time_now() + ": Web query response: '" + webResponseMsg + "'")

            try:
              if(numPackets == 0):
                if(len(webResponseMsg) > 290):
                  webResponseMsg = webResponseMsg[0:290]

                webIPCqueue.send(struct.pack('=LH' + str(len(webResponseMsg)) + 's', webMsgTime, webMsgID,
                       webResponseMsg.encode('ascii')), block=False)
              else:
                # In this case, block=False prevents blocking if the message
                # queue is too full for our message to fit. Instead, an
                # error is returned.
                msgTemp = struct.pack('=LH1s', webMsgTime, webMsgID, bytearray([numPackets]))
                webIPCqueue.send(msgTemp, block=False)
                for i in range(0, numPackets):
                  packet = webResponseMsg[i*290:i*290+290]
                  webIPCqueue.send(struct.pack('=LH' + str(len(packet)) + 's', webMsgTime, webMsgID,
                     packet.encode('ascii')), block=False)

            except sysv_ipc.BusyError:
              print(time_now() + ": Error: IPC queue full when trying to send response to web interface.")

      except sysv_ipc.BusyError:
        # No web message is waiting.
        pass

      ########################################################################
      # Report settings in MySQL DB every 30 seconds

      now = time.time()
      if (now > timeReport + 30):
        if db is not None:
          if(debugLevel >= 3):
            print("Storing in DB")
#  `timestamp` DATETIME,
#  `total_amps_max` FLOAT(10,7) NULL DEFAULT NULL,
#  `twc_id` VARCHAR(64),
#  `amps_offered` FLOAT(10,7) NULL DEFAULT NULL,
#  `current_amps` FLOAT(10,7) NULL DEFAULT NULL,
#  `state` TINYINT(3) UNSIGNED NULL DEFAULT NULL,
          timestamp_utc = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())

          for i in range(0, len(slaveTWCRoundRobin)):
            twc_id = "%02X%02X" % (slaveTWCRoundRobin[i].TWCID[0], slaveTWCRoundRobin[i].TWCID[1])
            db_query  = "INSERT INTO twc_data"
            db_query += " (`timestamp` , `total_amps_max`, `twc_id`, `amps_offered`, `current_amps`, `state`, `VIN_connected`)"
            db_query += " VALUES (%s, %s, %s, %s, %s, %s, %s)"
            db_values = (timestamp_utc, maxAmpsToDivideAmongSlaves, twc_id, \
                         slaveTWCRoundRobin[i].lastAmpsOffered, slaveTWCRoundRobin[i].reportedAmpsActual, \
                         slaveTWCRoundRobin[i].reportedState, slaveTWCRoundRobin[i].currentVIN)
            if(debugLevel >= 10):
              print("Query: %s, Values: %s" % (db_query, db_values))

            # MySQL connection drops after 8 hours, so execute could fail once.
            # A failed insert must never stop the heartbeats.
            try:
              cursor.execute(db_query, db_values)
              db.commit()
              if(debugLevel >= 3):
                print("Added entry to database for TWC " + twc_id)
            except Exception as e:
              print("Inserting values failed: %s" % e)
              print("Executing reconnect and insert")
              try:
                db.reconnect()
                cursor = db.cursor()
                cursor.execute(db_query, db_values)
                db.commit()
                print("Added entry to database after reconnect")
              except Exception as e2:
                print("Reconnect failed, skipping this entry: %s" % e2)

        # Accumulate energy delivered by all TWCs (master mode)
        totalAmps = 0
        if(fakeMaster == 1):
          totalAmps = total_amps_actual_all_twcs()
          kWhDelivered += ((supplyVolts * supplyPhases * totalAmps / 1000.0)
                           * (now - timeLastkWhDelivered) / 3600.0)
          timeLastkWhDelivered = now
          if(now - timeLastkWhSaved >= 300.0):
            timeLastkWhSaved = now
            save_status()

        # One summary line plus one line per TWC. This runs every 30 seconds
        # for as long as the service is up, so keep it short: the SD card
        # has to hold everything written here.
        if(debugLevel >= 2):
          print(time_now() + ": %.2fA available, %.2fA in use, %d TWCs, %.3f kWh delivered"
                % (maxAmpsToDivideAmongSlaves, totalAmps,
                   len(slaveTWCRoundRobin), kWhDelivered))
          for i in range(0, len(slaveTWCRoundRobin)):
            print(time_now() + ":  TWC %02X%02X: %05.2fA used, %05.2fA offered, state %d, VIN '%s'"
                  % (slaveTWCRoundRobin[i].TWCID[0], slaveTWCRoundRobin[i].TWCID[1],
                     slaveTWCRoundRobin[i].reportedAmpsActual,
                     slaveTWCRoundRobin[i].lastAmpsOffered,
                     slaveTWCRoundRobin[i].reportedState,
                     slaveTWCRoundRobin[i].currentVIN))
        timeReport = now


      ########################################################################
      # See if there's an incoming message on the RS485 interface.

      timeMsgRxStart = time.time()
      while True:
        now = time.time()
        dataLen = ser.inWaiting()
        if(dataLen == 0):
          if(msgLen == 0):
            # No message data waiting and we haven't received the
            # start of a new message yet. Break out of inner while
            # to continue at top of outer while loop where we may
            # decide to send a periodic message.
            break
          else:
            # No message data waiting but we've received a partial
            # message that we should wait to finish receiving.
            if(now - timeMsgRxStart >= 2.0):
              if(debugLevel >= 9):
                print(time_now() + ": Msg timeout (" + hex_str(ignoredData) +
                      ') ' + hex_str(msg[0:msgLen]))
              msgLen = 0
              ignoredData = bytearray()
              break

            time.sleep(0.025)
            continue
        else:
          dataLen = 1
          data = ser.read(dataLen)

        if(dataLen != 1):
          # This should never happen
          print("WARNING: No data available.")
          break

        timeMsgRxStart = now
        timeLastRx = now
        if(msgLen == 0 and data[0] != 0xc0):
          # We expect to find these non-c0 bytes between messages, so
          # we don't print any warning at standard debug levels.
          if(debugLevel >= 20):
            print("Ignoring byte %02X between messages." % (data[0]))
          ignoredData += data
          continue
        elif(msgLen > 0 and msgLen < 15 and data[0] == 0xc0):
          # If you see this when the program is first started, it
          # means we started listening in the middle of the TWC
          # sending a message so we didn't see the whole message and
          # must discard it. That's unavoidable.
          # If you see this any other time, it means there was some
          # corruption in what we received. It's normal for that to
          # happen every once in awhile but there may be a problem
          # such as incorrect termination or bias resistors on the
          # rs485 wiring if you see it frequently.
          if(debugLevel >= 10):
            print("Found end of message before full-length message received.  " \
                  "Discard and wait for new message.")

          # ser.read() returns bytes; the rest of the code
          # (and unescape_msg) needs a mutable bytearray.
          msg = bytearray(data)
          msgLen = 1
          continue

        if(msgLen == 0):
          msg = bytearray()
        msg += data
        msgLen += 1

        # Messages are usually 17 bytes or longer and end with \xc0\xfe.
        # However, when the network lacks termination and bias
        # resistors, the last byte (\xfe) may be corrupted or even
        # missing, and you may receive additional garbage bytes between
        # messages.
        #
        # TWCs seem to account for corruption at the end and between
        # messages by simply ignoring anything after the final \xc0 in a
        # message, so we use the same tactic. If c0 happens to be within
        # the corrupt noise between messages, we ignore it by starting a
        # new message whenever we see a c0 before 15 or more bytes are
        # received.
        #
        # Uncorrupted messages can be over 17 bytes long when special
        # values are "escaped" as two bytes. See notes in send_msg.
        #
        # To prevent most noise between messages, add a 120ohm
        # "termination" resistor in parallel to the D+ and D- lines.
        # Also add a 680ohm "bias" resistor between the D+ line and +5V
        # and a second 680ohm "bias" resistor between the D- line and
        # ground. See here for more information:
        #   https://www.ni.com/support/serial/resinfo.htm
        #   http://www.ti.com/lit/an/slyt514/slyt514.pdf
        # This explains what happens without "termination" resistors:
        #   https://e2e.ti.com/blogs_/b/analogwire/archive/2016/07/28/rs-485-basics-when-termination-is-necessary-and-how-to-do-it-properly
        if(msgLen >= 16 and data[0] == 0xc0):
          break
      # while true

      if(msgLen >= 16):
        # Reset msgLen BEFORE unescaping: a failure in unescape_msg must not
        # leave a partial message in place to fail again on every pass.
        rxLen = msgLen
        msgLen = 0
        msg = unescape_msg(msg, rxLen)
              
        msgRxCount += 1

        # When the sendTWCMsg web command is used to send a message to the
        # TWC, it sets lastTWCResponseMsg = b''.  When we see that here,
        # set lastTWCResponseMsg to any unusual message received in response
        # to the sent message.  Never set lastTWCResponseMsg to a commonly
        # repeated message like master or slave linkready, heartbeat, or
        # voltage/kWh report.
        if(lastTWCResponseMsg == b''
           and msg[0:2] != b'\xFB\xE0' and msg[0:2] != b'\xFD\xE0'
           and msg[0:2] != b'\xFC\xE1' and msg[0:2] != b'\xFB\xE2'
           and msg[0:2] != b'\xFD\xE2' and msg[0:2] != b'\xFB\xEB'
           and msg[0:2] != b'\xFD\xEB' and msg[0:2] != b'\xFD\xE0'
        ):
          lastTWCResponseMsg = msg

        if(debugLevel >= 9):
          print("Rx@" + time_now() + ": (" + hex_str(ignoredData) + ') ' \
                + hex_str(msg) + "")

        ignoredData = bytearray()

        # After unescaping special values and removing the leading and
        # trailing C0 bytes, the messages we know about are always 14 bytes
        # long in original TWCs, or 16 bytes in newer TWCs (protocolVersion
        # == 2).
        if(len(msg) != 14 and len(msg) != 16 and len(msg) != 20):
          # In firmware 4.5.3, FD EB (kWh and voltage report), FD ED, FD
          # EE, FD EF, FD F1, and FB A4 messages are length 20 while most
          # other messages are length 16. I'm not sure if there are any
          # length 14 messages remaining.
          print(time_now() + ": ERROR: Ignoring message of unexpected length %d: %s" % \
                 (len(msg), hex_str(msg)))
          continue

        checksumExpected = msg[len(msg) - 1]
        checksum = 0
        for i in range(1, len(msg) - 1):
          checksum += msg[i]

        if((checksum & 0xFF) != checksumExpected):
          print("ERROR: Checksum %X does not match %02X.  Ignoring message: %s" %
              (checksum, checksumExpected, hex_str(msg)))
          continue

        if(fakeMaster == 1):
          ############################
          # Pretend to be a master TWC

          foundMsgMatch = False
          # We end each regex message search below with \Z instead of $
          # because $ will match a newline at the end of the string or the
          # end of the string (even without the re.MULTILINE option), and
          # sometimes our strings do end with a newline character that is
          # actually the CRC byte with a value of 0A or 0D.
          # EZ ADDED START
          msgMatch = re.search(b"^\xfd\xb1(..)\x00\x00.+\Z", msg, re.DOTALL)
          if msgMatch and foundMsgMatch == False:
            # Handle acknowledgement of Start command
            foundMsgMatch = True
            senderID = msgMatch.group(1)

          msgMatch = re.search(b"^\xfd\xb2(..)\x00\x00.+\Z", msg, re.DOTALL)
          if msgMatch and foundMsgMatch == False:
            # Handle acknowledgement of Stop command
            foundMsgMatch = True
            senderID = msgMatch.group(1)                
          # EZ ADDED END
          msgMatch = re.search(b'^\xfd\xe2(..)(.)(..)\x00\x00\x00\x00\x00\x00.+\Z', msg, re.DOTALL)
          if(msgMatch and foundMsgMatch == False):
            # Handle linkready message from slave.
            #
            # We expect to see one of these before we start sending our
            # own heartbeat message to slave.
            # Once we start sending our heartbeat to slave once per
            # second, it should no longer send these linkready messages.
            # If slave doesn't hear master's heartbeat for around 10
            # seconds, it sends linkready once per 10 seconds and starts
            # flashing its red LED 4 times with the top green light on.
            # Red LED stops flashing if we start sending heartbeat
            # again.
            foundMsgMatch = True
            senderID = msgMatch.group(1)
            sign = msgMatch.group(2)
            maxAmps = ((msgMatch.group(3)[0] << 8) + msgMatch.group(3)[1]) / 100

            if(debugLevel >= 1):
              print(time_now() + ": %.2f amp slave TWC %02X%02X is ready to link.  Sign: %s" % \
                  (maxAmps, senderID[0], senderID[1],
                  hex_str(sign)))

            if(maxAmps >= 80):
              # U.S. chargers need a spike to 21A to cancel a 6A
              # charging limit imposed in an Oct 2017 Tesla car
              # firmware update. See notes where
              # spikeAmpsToCancel6ALimit is used.
              spikeAmpsToCancel6ALimit = 21
            else:
              # EU chargers need a spike to only 16A.  This value
              # comes from a forum post and has not been directly
              # tested.
              spikeAmpsToCancel6ALimit = 16

            if(senderID == fakeTWCID):
              print(time_now + ": Slave TWC %02X%02X reports same TWCID as master.  " \
                    "Slave should resolve by changing its TWCID." % \
                    (senderID[0], senderID[1]))
              # I tested sending a linkready to a real master with the
              # same TWCID as master and instead of master sending back
              # its heartbeat message, it sent 5 copies of its
              # linkready1 and linkready2 messages. Those messages
              # will prompt a real slave to pick a new random value
              # for its TWCID.
              #
              # We mimic that behavior by setting numInitMsgsToSend =
              # 10 to make the idle code at the top of the for()
              # loop send 5 copies of linkready1 and linkready2.
              numInitMsgsToSend = 10
              continue

            # We should always get this linkready message at least once
            # and generally no more than once, so this is a good
            # opportunity to add the slave to our known pool of slave
            # devices.
            slaveTWC = new_slave(senderID, maxAmps)

            if(slaveTWC.protocolVersion == 1 and slaveTWC.minAmpsTWCSupports == 6):
              if(len(msg) == 14):
                slaveTWC.protocolVersion = 1
                slaveTWC.minAmpsTWCSupports = 5
              elif(len(msg) == 16):
                slaveTWC.protocolVersion = 2
                slaveTWC.minAmpsTWCSupports = 6

              if(debugLevel >= 1):
                print(time_now() + ": Set slave TWC %02X%02X protocolVersion to %d, minAmpsTWCSupports to %d." % \
                     (senderID[0], senderID[1], slaveTWC.protocolVersion, slaveTWC.minAmpsTWCSupports))

            # We expect maxAmps to be 80 on U.S. chargers and 32 on EU
            # chargers. Either way, don't allow
            # slaveTWC.wiringMaxAmps to be greater than maxAmps.
            if(slaveTWC.wiringMaxAmps > maxAmps):
              print("\n\n!!! DANGER DANGER !!!\nYou have set wiringMaxAmpsPerTWC to "
                    + str(wiringMaxAmpsPerTWC)
                    + " which is greater than the max "
                    + str(maxAmps) + " amps your charger says it can handle.  " \
                    "Please review instructions in the source code and consult an " \
                    "electrician if you don't know what to do.")
              slaveTWC.wiringMaxAmps = maxAmps / 4

            # Make sure we print one SHB message after a slave
            # linkready message is received by clearing
            # lastHeartbeatDebugOutput. This helps with debugging
            # cases where I can't tell if we responded with a
            # heartbeat or not.
            slaveTWC.lastHeartbeatDebugOutput = ''

            slaveTWC.timeLastRx = time.time()
            slaveTWC.send_master_heartbeat()
          else:
            msgMatch = re.search(b'\A\xfd\xe0(..)(..)(.......+?).\Z', msg, re.DOTALL)
          if(msgMatch and foundMsgMatch == False):
            # Handle heartbeat message from slave.
            #
            # These messages come in as a direct response to each
            # heartbeat message from master. Slave does not send its
            # heartbeat until it gets one from master first.
            # A real master sends heartbeat to a slave around once per
            # second, so we do the same near the top of this for()
            # loop. Thus, we should receive a heartbeat reply from the
            # slave around once per second as well.
            foundMsgMatch = True
            senderID = msgMatch.group(1)
            receiverID = msgMatch.group(2)
            heartbeatData = msgMatch.group(3)

            try:
              slaveTWC = slaveTWCs[senderID]
            except KeyError:
              # Normally, a slave only sends us a heartbeat message if
              # we send them ours first, so it's not expected we would
              # hear heartbeat from a slave that's not in our list.
              print(time_now() + ": ERROR: Received heartbeat message from " \
                      "slave %02X%02X that we've not met before." % \
                      (senderID[0], senderID[1]))
              continue

            if(fakeTWCID == receiverID):
              slaveTWC.receive_slave_heartbeat(heartbeatData)
            else:
              # I've tried different fakeTWCID values to verify a
              # slave will send our fakeTWCID back to us as
              # receiverID. However, I once saw it send receiverID =
              # 0000.
              # I'm not sure why it sent 0000 and it only happened
              # once so far, so it could have been corruption in the
              # data or an unusual case.
              if(debugLevel >= 1):
                print(time_now() + ": WARNING: Slave TWC %02X%02X status data: " \
                      "%s sent to unknown TWC %02X%02X." % \
                    (senderID[0], senderID[1],
                    hex_str(heartbeatData), receiverID[0], receiverID[1]))
          else:
            msgMatch = re.search(b'\A\xfd\xeb(..)(..)(.+?).\Z', msg, re.DOTALL)
          if(msgMatch and foundMsgMatch == False):
            # Handle kWh total and voltage message from slave.
            #
            # This message can only be generated by TWCs running newer
            # firmware.  I believe it's only sent as a response to a
            # message from Master in this format:
            #   FB EB <Master TWCID> <Slave TWCID> 00 00 00 00 00 00 00 00 00
            # According to FuzzyLogic, this message has the following
            # format on an EU (3-phase) TWC:
            #   FD EB <Slave TWCID> 00000038 00E6 00F1 00E8 00
            #   00000038 (56) is the total kWh delivered to cars
            #     by this TWC since its construction.
            #   00E6 (230) is voltage on phase A
            #   00F1 (241) is voltage on phase B
            #   00E8 (232) is voltage on phase C
            #
            # I'm guessing in world regions with two-phase power that
            # this message would be four bytes shorter, but the pattern
            # above will match a message of any length that starts with
            # FD EB.
            # EZ Copied kWh and Phase information from newer version (NGardiner)
            foundMsgMatch = True
            senderID = msgMatch.group(1)
            lifetimekWh = msgMatch.group(2)
            kWh = (
                (lifetimekWh[0] << 24)
                + (lifetimekWh[1] << 16)
                + (lifetimekWh[2] << 8)
                + lifetimekWh[3]
            )
            vPhaseA = msgMatch.group(3)
            voltsPhaseA = (vPhaseA[0] << 8) + vPhaseA[1]
            vPhaseB = msgMatch.group(4)
            voltsPhaseB = (vPhaseB[0] << 8) + vPhaseB[1]
            vPhaseC = msgMatch.group(5)
            voltsPhaseC = (vPhaseC[0] << 8) + vPhaseC[1]
            data = msgMatch.group
            if(debugLevel >= 1):
              print(time_now() + ": Slave TWC %02X%02X: Delivered %d kWh, voltage per phase: (%d, %d, %d).",
              senderID[0],
              senderID[1],
              kWh,
              voltsPhaseA,
              voltsPhaseB,
              voltsPhaseC,
              extra={
                  "logtype": "slave_status",
                  "TWCID": senderID,
                  "kWh": kWh,
                  "voltsPerPhase": [voltsPhaseA, voltsPhaseB, voltsPhaseC],
              },
          )                                                     
          # EZ Added VIN decoding from newer version (NGardiner)
          else:
            msgMatch = re.search(
                b"\A\xfd(\xee|\xef|\xf1)(..)(.+?).\Z", msg, re.DOTALL
            )
          if msgMatch and foundMsgMatch == False:
            # Get 7 characters of VIN from slave. (XE is first 7, XF second 7)
            #
            # This message can only be generated by TWCs running newer
            # firmware.  I believe it's only sent as a response to a
            # message from Master in this format:
            #   FB EE <Master TWCID> <Slave TWCID> 00 00 00 00 00 00 00 00 00

            # Response message is FD EE <Slave TWCID> VV VV VV VV VV VV VV where VV is an ascii character code
            # representing a letter or number. VV will be all zero when car CAN communication is disabled
            # (DIP switch 2 down) or when a non-Tesla vehicle is plugged in using something like a JDapter.

            foundMsgMatch = True
            vinPart = msgMatch.group(1)
            senderID = msgMatch.group(2)
            data = msgMatch.group(3)

            if(debugLevel >= 1):
              print(time_now() + ": Slave TWC %02X%02X reported VIN data: %s."
              % (senderID[0], senderID[1], hex_str(data)))
            slaveTWC = slaveTWCs[senderID]
            if vinPart == b"\xee":
              vinPart = 0
            if vinPart == b"\xef":
              vinPart = 1
            if vinPart == b"\xf1":
              vinPart = 2
            slaveTWC.VINData[vinPart] = data.decode("utf-8").rstrip("\x00")
            if vinPart < 2:
              vinPart += 1
              # master.queue_background_task(
              #    {
              #        "cmd": "getVehicleVIN",
              #        "slaveTWC": senderID,
              #        "vinPart": str(vinPart),
              #    }
              #)
              getVehicleVIN(senderID, str(vinPart))
            else:
              potentialVIN = "".join(slaveTWC.VINData)

              # Ensure we have a valid VIN
              vinValid = True
              if len(potentialVIN) != 17 and len(potentialVIN) != 0:
                vinValid = False
              if vinValid and len(potentialVIN) == 17:
                potentialVIN = potentialVIN.upper()
                check = potentialVIN[8]
                if check == "X":
                  check = 10
                elif check.isdigit():
                  check = int(check)
                else:
                  vinValid = False
              if vinValid and len(potentialVIN) == 17:
                weights = [
                    8,
                    7,
                    6,
                    5,
                    4,
                    3,
                    2,
                    10,
                    0,
                    9,
                    8,
                    7,
                    6,
                    5,
                    4,
                    3,
                    2,
                ]
                replaceValues = {
                    "A": 1,
                    "B": 2,
                    "C": 3,
                    "D": 4,
                    "E": 5,
                    "F": 6,
                    "G": 7,
                    "H": 8,
                    "J": 1,
                    "K": 2,
                    "L": 3,
                    "M": 4,
                    "N": 5,
                    "P": 7,
                    "R": 9,
                    "S": 2,
                    "T": 3,
                    "U": 4,
                    "V": 5,
                    "W": 6,
                    "X": 7,
                    "Y": 8,
                    "Z": 9,
                    "1": 1,
                    "2": 2,
                    "3": 3,
                    "4": 4,
                    "5": 5,
                    "6": 6,
                    "7": 7,
                    "8": 8,
                    "9": 9,
                    "0": 0,
                }

                sum = 0
                for digit, weight in zip(potentialVIN, weights):
                  if digit not in replaceValues:
                    vinValid = False
                    break
                  sum += replaceValues[digit] * weight
                if sum % 11 != check:
                  vinValid = False

              if vinValid:
                # Record Vehicle VIN
                if(debugLevel >= 10 and potentialVIN != ""):
                  print(time_now() + ": Assigning VIN %s to TWC %02X%02X"
                    % (potentialVIN, slaveTWC.TWCID[0], slaveTWC.TWCID[1]))
                if(debugLevel >= 10 and potentialVIN == ""):
                  print(time_now() + ": TWC %02X%02X reports no car VIN"
                    % (slaveTWC.TWCID[0], slaveTWC.TWCID[1]))
                slaveTWC.currentVIN = potentialVIN
                # Only a real VIN ends the grace period. A car that has just
                # been plugged in answers with all zeros for the first several
                # seconds, and treating that as "identified" would block it
                # while it is still waking up. A car that never answers is
                # still blocked, by the grace period running out.
                if(potentialVIN != ""):
                  slaveTWC.vinReadDone = True
                vinPart += 1
              else:
                # Unfortunately the VIN was not received correctly.
                if(debugLevel >= 1):
                  print(time_now() + ": VIN not received correctly")
                getVehicleVIN(slaveTWC.TWCID, 0)

            if(debugLevel >= 1):
              print(time_now() + ": Current VIN string is: %s at part %d."
              % (str(slaveTWC.VINData), vinPart))
          # EZ END VIN parsing added

          else:
            msgMatch = re.search(b'\A\xfc(\xe1|\xe2)(..)(.)\x00\x00\x00\x00\x00\x00\x00\x00.+\Z', msg, re.DOTALL)
          if(msgMatch and foundMsgMatch == False):
            foundMsgMatch = True
            print(time_now() + " ERROR: TWC is set to Master mode so it can't be controlled by TWCManager.  " \
                   "Search installation instruction PDF for 'rotary switch' and set " \
                   "switch so its arrow points to F on the dial.")
          if(foundMsgMatch == False):
            print(time_now() + ": *** UNKNOWN MESSAGE FROM SLAVE:" + hex_str(msg)
                  + "\nPlease private message user CDragon at http://teslamotorsclub.com " \
                  "with a copy of this error.")
        else: # fakeMaster <> 1
          ###########################
          # Pretend to be a slave TWC

          foundMsgMatch = False
          msgMatch = re.search(b'\A\xfc\xe1(..)(.)\x00\x00\x00\x00\x00\x00\x00\x00+?.\Z', msg, re.DOTALL)
          if(msgMatch and foundMsgMatch == False):
            # Handle linkready1 from master.
            # See notes in send_master_linkready1() for details.
            foundMsgMatch = True
            senderID = msgMatch.group(1)
            sign = msgMatch.group(2)

            masterTWCID = senderID

            # This message seems to always contain seven 00 bytes in its
            # data area. If we ever get this message with non-00 data
            # we'll print it as an unexpected message.
            if(debugLevel >= 1):
              print(time_now() + ": Master TWC %02X%02X Linkready1.  Sign: %s" % \
                  (senderID[0], senderID[1], hex_str(sign)))

            if(senderID == fakeTWCID):
              master_id_conflict()

          # Other than picking a new fakeTWCID if ours conflicts with
          # master, it doesn't seem that a real slave will make any
          # sort of direct response when sent a master's linkready1 or
          # linkready2.

          else:
            msgMatch = re.search(b'\A\xfb\xe2(..)(.)\x00\x00\x00\x00\x00\x00\x00\x00+?.\Z', msg, re.DOTALL)
          if(msgMatch and foundMsgMatch == False):
            # Handle linkready2 from master.
            # See notes in send_master_linkready2() for details.
            foundMsgMatch = True
            senderID = msgMatch.group(1)
            sign = msgMatch.group(2)

            masterTWCID = senderID

            # This message seems to always contain seven 00 bytes in its
            # data area. If we ever get this message with non-00 data
            # we'll print it as an unexpected message.

            if(debugLevel >= 1):
              print(time_now() + ": Master TWC %02X%02X Linkready2.  Sign: %s" % \
                  (senderID[0], senderID[1], hex_str(sign)))

            if(senderID == fakeTWCID):
              master_id_conflict()
          else:
            msgMatch = re.search(b'\A\xfb\xe0(..)(..)(.......+?).\Z', msg, re.DOTALL)
          if(msgMatch and foundMsgMatch == False):
            # Handle heartbeat message from Master.
            foundMsgMatch = True
            senderID = msgMatch.group(1)
            receiverID = msgMatch.group(2)
            heartbeatData = msgMatch.group(3)

            masterTWCID = senderID
            try:
              slaveTWC = slaveTWCs[receiverID]
            except KeyError:
              slaveTWC = new_slave(receiverID, 80)

            slaveTWC.masterHeartbeatData = heartbeatData

            if(receiverID != fakeTWCID):
              # This message was intended for another slave.
              # Ignore it.
              if(debugLevel >= 11):
                print(time_now() + ": Master %02X%02X sent " \
                    "heartbeat message %s to receiver %02X%02X " \
                    "that isn't our fake slave." % \
                    (senderID[0], senderID[1],
                    hex_str(heartbeatData),
                    receiverID[0], receiverID[1]))
              continue

            amps = (slaveHeartbeatData[1] << 8) + slaveHeartbeatData[2]
            kWhDelivered += (((240 * (amps/100)) / 1000 / 60 / 60) * (now - timeLastkWhDelivered))
            timeLastkWhDelivered = now
            if(time.time() - timeLastkWhSaved >= 300.0):
              timeLastkWhSaved = now
              if(debugLevel >= 9):
                print(time_now() + ": Fake slave has delivered %.3fkWh" % \
                   (kWhDelivered))
              save_status()

            if(heartbeatData[0] == 0x07):
              # Lower amps in use (not amps allowed) by 2 for 10
              # seconds. Set state to 07.
              slaveHeartbeatData[0] = heartbeatData[0]
              timeToRaise2A = now + 10
              amps -= 280
              slaveHeartbeatData[3] = ((amps >> 8) & 0xFF)
              slaveHeartbeatData[4] = (amps & 0xFF)
            elif(heartbeatData[0] == 0x06):
              # Raise amp setpoint by 2 permanently and reply with
              # state 06.  After 44 seconds, report state 0A.
              timeTo0Aafter06 = now + 44
              slaveHeartbeatData[0] = heartbeatData[0]
              amps += 200
              slaveHeartbeatData[1] = ((amps >> 8) & 0xFF)
              slaveHeartbeatData[2] = (amps & 0xFF)
              amps -= 80
              slaveHeartbeatData[3] = ((amps >> 8) & 0xFF)
              slaveHeartbeatData[4] = (amps & 0xFF)
            elif(heartbeatData[0] == 0x05 or heartbeatData[0] == 0x08 or heartbeatData[0] == 0x09):
              if(((heartbeatData[1] << 8) + heartbeatData[2]) > 0):
                # A real slave mimics master's status bytes [1]-[2]
                # representing max charger power even if the master
                # sends it a crazy value.
                slaveHeartbeatData[1] = heartbeatData[1]
                slaveHeartbeatData[2] = heartbeatData[2]

                ampsUsed = (heartbeatData[1] << 8) + heartbeatData[2]
                ampsUsed -= 80
                slaveHeartbeatData[3] = ((ampsUsed >> 8) & 0xFF)
                slaveHeartbeatData[4] = (ampsUsed & 0xFF)
            elif(heartbeatData[0] == 0):
              if(timeTo0Aafter06 > 0 and timeTo0Aafter06 < now):
                timeTo0Aafter06 = 0
                slaveHeartbeatData[0] = 0x0A
              elif(timeToRaise2A > 0 and timeToRaise2A < now):
                # Real slave raises amps used by 2 exactly 10
                # seconds after being sent into state 07. It raises
                # a bit slowly and sets its state to 0A 13 seconds
                # after state 07. We aren't exactly emulating that
                # timing here but hopefully close enough.
                timeToRaise2A = 0
                amps -= 80
                slaveHeartbeatData[3] = ((amps >> 8) & 0xFF)
                slaveHeartbeatData[4] = (amps & 0xFF)
                slaveHeartbeatData[0] = 0x0A
            elif(heartbeatData[0] == 0x02):
              print(time_now() + ": Master heartbeat contains error %ld: %s" % \
                      (heartbeatData[1], hex_str(heartbeatData)))
            else:
              print(time_now() + ": UNKNOWN MHB state %s" % \
                      (hex_str(heartbeatData)))

            # Slaves always respond to master's heartbeat by sending
            # theirs back.
            slaveTWC.send_slave_heartbeat(senderID)
            slaveTWC.print_status(slaveHeartbeatData)
          else:
            msgMatch = re.search(b'\A\xfc\x1d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00+?.\Z', msg, re.DOTALL)
          if(msgMatch and foundMsgMatch == False):
            # Handle 2-hour idle message
            #
            # This message is sent from a Master TWC three times in a
            # row every 2 hours:
            #   c0 fc 1d 00 00 00 00 00 00 00 00 00 00 00 1d c0
            #
            # I'd say this is used to indicate the master is still
            # alive, but it doesn't contain the Master's TWCID or any other
            # data so I don't see what any receiving TWC can do with it.
            #
            # I suspect this message is only sent when the master
            # doesn't see any other TWCs on the network, so I don't
            # bother to have our fake master send these messages being
            # as there's no point in playing a fake master with no
            # slaves around.
            foundMsgMatch = True
            if(debugLevel >= 1):
              print(time_now() + ": Received 2-hour idle message from Master.")
          else:
            msgMatch = re.search(b'\A\xfd\xe2(..)(.)(..)\x00\x00\x00\x00\x00\x00.+\Z', msg, re.DOTALL)
          if(msgMatch and foundMsgMatch == False):
            # Handle linkready message from slave on network that
            # presumably isn't us.
            foundMsgMatch = True
            senderID = msgMatch.group(1)
            sign = msgMatch.group(2)
            maxAmps = ((msgMatch.group(3)[0] << 8) + msgMatch.group(3)[1]) / 100
            if(debugLevel >= 1):
              print(time_now() + ": %.2f amp slave TWC %02X%02X is ready to link.  Sign: %s" % \
                  (maxAmps, senderID[0], senderID[1],
                  hex_str(sign)))
            if(senderID == fakeTWCID):
              print(time_now() + ": ERROR: Received slave heartbeat message from " \
                      "slave %02X%02X that has the same TWCID as our fake slave." % \
                      (senderID[0], senderID[1]))
              continue

            new_slave(senderID, maxAmps)
          else:
            msgMatch = re.search(b'\A\xfd\xe0(..)(..)(.......+?).\Z', msg, re.DOTALL)
          if(msgMatch and foundMsgMatch == False):
            # Handle heartbeat message from slave on network that
            # presumably isn't us.
            foundMsgMatch = True
            senderID = msgMatch.group(1)
            receiverID = msgMatch.group(2)
            heartbeatData = msgMatch.group(3)

            if(senderID == fakeTWCID):
              print(time_now() + ": ERROR: Received slave heartbeat message from " \
                      "slave %02X%02X that has the same TWCID as our fake slave." % \
                      (senderID[0], senderID[1]))
              continue

            try:
              slaveTWC = slaveTWCs[senderID]
            except KeyError:
              # Slave is unlikely to send another linkready since it's
              # already linked with a real Master TWC, so just assume
              # it's 80A.
              slaveTWC = new_slave(senderID, 80)

            slaveTWC.print_status(heartbeatData)
          else:
            msgMatch = re.search(b'\A\xfb\xeb(..)(..)(\x00\x00\x00\x00\x00\x00\x00\x00\x00+?).\Z', msg, re.DOTALL)
          if(msgMatch and foundMsgMatch == False):
            # Handle voltage request message.  This is only supported in
            # Protocol 2 so we always reply with a 16-byte message.
            foundMsgMatch = True
            senderID = msgMatch.group(1)
            receiverID = msgMatch.group(2)

            if(senderID == fakeTWCID):
              print(time_now() + ": ERROR: Received voltage request message from " \
                      "TWC %02X%02X that has the same TWCID as our fake slave." % \
                      (senderID[0], senderID[1]))
              continue

            if(debugLevel >= 8):
              print(time_now() + ": VRQ from %02X%02X to %02X%02X" % \
                  (senderID[0], senderID[1], receiverID[0], receiverID[1]))

            if(receiverID == fakeTWCID):
              kWhCounter = int(kWhDelivered)
              kWhPacked = bytearray([((kWhCounter >> 24) & 0xFF),
                            ((kWhCounter >> 16) & 0xFF),
                            ((kWhCounter >> 8) & 0xFF),
                            (kWhCounter & 0xFF)])
              print(time_now() + ": VRS %02X%02X: %dkWh (%s) %dV %dV %dV" % \
                  (fakeTWCID[0], fakeTWCID[1],
                  kWhCounter, hex_str(kWhPacked), 240, 0, 0))
              send_msg(bytearray(b'\xFD\xEB') + fakeTWCID
                       + kWhPacked
                       + bytearray(b'\x00\xF0\x00\x00\x00\x00\x00'))
          else:
            msgMatch = re.search(b'\A\xfd\xeb(..)(.........+?).\Z', msg, re.DOTALL)
          if(msgMatch and foundMsgMatch == False):
            # Handle voltage response message.
            # Example US value:
            #   FD EB 7777 00000014 00F6 0000 0000 00
            # EU value (3 phase power):
            #   FD EB 7777 00000038 00E6 00F1 00E8 00
            foundMsgMatch = True
            senderID = msgMatch.group(1)
            data = msgMatch.group(2)
            kWhCounter = (data[0] << 24) + (data[1] << 16) + (data[2] << 8) + data[3]
            voltsPhaseA = (data[4] << 8) + data[5]
            voltsPhaseB = (data[6] << 8) + data[7]
            voltsPhaseC = (data[8] << 8) + data[9]

            if(senderID == fakeTWCID):
              print(time_now() + ": ERROR: Received voltage response message from " \
                      "TWC %02X%02X that has the same TWCID as our fake slave." % \
                      (senderID[0], senderID[1]))
              continue

            if(debugLevel >= 1):
              print(time_now() + ": VRS %02X%02X: %dkWh %dV %dV %dV" % \
                  (senderID[0], senderID[1],
                  kWhCounter, voltsPhaseA, voltsPhaseB, voltsPhaseC))

          if(foundMsgMatch == False):
            print(time_now() + ": ***UNKNOWN MESSAGE from master: " + hex_str(msg))

    except KeyboardInterrupt:
      print("Exiting after background tasks complete...")
      break

    except Exception as e:
      # Print info about unhandled exceptions, then continue.  Search for
      # 'Traceback' to find these in the log.
      traceback.print_exc()

      # Sleep a second so the user might see the error.
      time.sleep(1)


  ser.close()

  if (db.is_connected()):
    db.close()
    cursor.close()
    print("MySQL connection is closed")
  print("DONE.")

#
# End main program
#
##############################

if __name__ == '__main__':
  main()
