#!/usr/bin/perl

################################################################
#
#  Copyright notice
#
#  (c) 2017
#  Copyright: Alexander Schulz
#  All rights reserved
#
#  This script free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  The GNU General Public License can be found at
#  http://www.gnu.org/copyleft/gpl.html.
#  A copy is found in the textfile GPL.txt and important notices to the license
#  from the author is found in LICENSE.txt distributed with these scripts.
#
#  This script is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  This copyright notice MUST APPEAR in all copies of the script!
#
#  Homepage:  http://s6z.de
#
# $Id$

my $ver = '0.1 alpha';
my $hello = "FHEM starter / watchdog v.$ver";

use strict;
use warnings;
#use lib '.';
#use IO::Socket;
#use Time::HiRes qw(gettimeofday);
#use Scalar::Util qw(looks_like_number);
use POSIX;
#use POSIX qw(setsid);
use Getopt::Long;
use Scalar::Util qw(looks_like_number);

    # Test Shared Memory : http://perldoc.perl.org/IPC/SharedMem.html
    #use IPC::SysV qw(IPC_PRIVATE S_IRUSR S_IWUSR IPC_CREAT IPC_EXCL S_IRWXU);
    #use IPC::SharedMem;
    #my $shm = IPC::SharedMem->new(IPC_PRIVATE, 8, IPC_CREAT | 0666);
    #$shm->write(pack("S", 4711), 2, 2);
    #my $data = $shm->read(0, 2);
    #my $ds = $shm->stat;
    #$shm->remove;

    # Named pipes : http://perldoc.perl.org/perlipc.html#Named-Pipes


use constant {
  DEFAULT_CFG_FILE          => 'watchdog.cfg',
  DEFAULT_VERBOSE_LEVEL     => 1,
  
  KEY_START                 => 'start',
  KEY_CHECK_INTERVAL        => 'check_interval',
  KEY_INSTANCES             => 'instances',
  KEY_BASE_DIR              => 'base_dir',
  KEY_START_COMMAND         => 'start_command',
  KEY_PID_FILE              => "pid_file",
  KEY_PID                   => "pid",
  KEY_HEARTBEAT_FILE        => 'heartbeat_file',
  KEY_STATE                 => 'state',
  KEY_TIMESTAMP             => 'timestamp',
  KEY_ALIVE_TIMEOUT         => 'alive_timeout',
  KEY_TERM_TIMEOUT          => 'term_timeout',
  KEY_START_TIMEOUT         => 'start_timeout',
  KEY_WAIT_BEFORE_NEXT      => 'wait_before_next',
  
  KEY_DEFAULT_BASE_DIR      => 'default_base_dir',
  KEY_DEFAULT_ALIVE_TIMEOUT => 'default_alive_timeout',
  KEY_DEFAULT_START_TIMEOUT => 'default_start_timeout',
  KEY_DEFAULT_TERM_TIMEOUT  => 'default_term_timeout',
  
  STATE_INIT                => 'init',
  STATE_INVALIDE            => 'invalide',
  STATE_STARTING            => 'starting',
  STATE_ALIVE               => 'alive',
  STATE_DEAD                => 'dead',
  STATE_AWAITING_DEATH      => 'waiting_death',
  STATE_TERMINATED          => 'terminated',
  STATE_TARGET_ERROR        => 'target_error'
};


sub readCfg ($);
sub signalHandling();
sub processInstance($);
sub isVerbose($);
sub logV($$);
sub dumpInstanceData($);
sub getCurrentTime();
sub setStatus($$);
sub startProg($);
sub checkPID($);
sub readPid($);
sub createPidFile($);
sub deleteFile($);
sub checkAliveTimeout($);
sub checkStartTimeout($);
sub checkTermTimeout($);
sub checkWaitBeforeTime($);
sub checkPidFile($);
sub checkHBFile($$);
sub checkAnotherInstancePid($);
sub checkTimeout($$);
sub checkFileExist($);

# global variables
my $sig_term = 0;               # if set to 1, terminate


# main

# init
signalHandling();

# process command line arguments:
my $cfg_file = DEFAULT_CFG_FILE;
my $verbose  = DEFAULT_VERBOSE_LEVEL;
my $help;
my $versionf;
GetOptions ('help|h'          => \$help,        # flag
            'config|c=s'      => \$cfg_file,    # string
            'verbose|v=i'     => \$verbose,     # numeric
            'version|ver|ve'  => \$versionf,    # flag
            'quiet'   => sub { $verbose = 0 });   # sub

# comand line option: help
if($help) {
  print(STDOUT "$hello\n");
  print(STDOUT "usage: watchdog.pl [-c config file] [-h] [-v verbose level]\n");
  print(STDOUT "avialable options: \n");
  print(STDOUT "   -c, --config     config file (default: ".DEFAULT_CFG_FILE.")\n");
  print(STDOUT "   -h, --help       display this help and exit\n");
  print(STDOUT "   -v, --verbose    define verbose level (default = 1)\n");
  print(STDOUT "                    (0: silent, 1: error, 2: warn, 3:info, 4: debug, 5: trace)\n");
  print(STDOUT "   -q, --quiet      set verbose to 0\n");
  print(STDOUT "       --version    output version information and exit\n");

  exit(0);
}

# comand line option: version
if($versionf) {
  print(STDOUT "$hello\n");
  print(STDOUT "Copyright (C) 2017 \n");
  print(STDOUT "License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.\n");
  print(STDOUT "This is free software: you are free to change and redistribute it.\n");
  print(STDOUT "There is NO WARRANTY, to the extent permitted by law.\n\n");
  print(STDOUT "Written by Alexander Schulz (www.s6z.de)\n");

  exit(0);
}

# hello
logV(1,"$hello\n\n");
#logV(5,"verbose level: $verbose\n");

# Get our configuration information
logV(5,"use configuration file: $cfg_file");
if (my $err = readCfg($cfg_file)) {
    print(STDERR "=> could not read configuration\n");
    print(STDERR $err, "\n");
    exit(1);
}
logV(5, "=> ok\n");

my $instList = $CFG::CFG{+KEY_START};
my $check_interval = $CFG::CFG{+KEY_CHECK_INTERVAL};
$check_interval = 1 unless $check_interval;
my $default_base_dir = $CFG::CFG{+KEY_DEFAULT_BASE_DIR};
my $default_alive_timeout = $CFG::CFG{+KEY_DEFAULT_ALIVE_TIMEOUT};
my $default_start_timeout = $CFG::CFG{+KEY_DEFAULT_START_TIMEOUT};
my $default_term_timeout = $CFG::CFG{+KEY_DEFAULT_TERM_TIMEOUT};
my $pidFile = $CFG::CFG{+KEY_PID_FILE};
my $lastStartTime = 0;

if($pidFile) {
  logV(5,"create PID:".$pidFile."\n");
  # TODO: checkAnotherInstancePid
  createPidFile($pidFile);
  #logV(5, "PID: ".readPid($pidFile));
}

# create work map
logV(5,"create work instance map \n");
my $workmap;
foreach my $inst_name (@{$instList})
{
    logV(4, " - add monitoring instance: ".$inst_name."\n");
    # state invalid
    $workmap->{$inst_name}->{+KEY_STATE}=STATE_INVALIDE;
    
    # timestamp
    $workmap->{$inst_name}->{+KEY_TIMESTAMP}=getCurrentTime();
    
    # base dir KEY_BASE_DIR
    if($CFG::CFG{+KEY_INSTANCES}{$inst_name}{+KEY_BASE_DIR}) {
      $workmap->{$inst_name}->{+KEY_BASE_DIR}=$CFG::CFG{+KEY_INSTANCES}{$inst_name}{+KEY_BASE_DIR};
    } else {
      $workmap->{$inst_name}->{+KEY_BASE_DIR}=$default_base_dir;
    }
    
    # start command KEY_START_COMMAND
    if($CFG::CFG{+KEY_INSTANCES}{$inst_name}{+KEY_START_COMMAND}) {
      $workmap->{$inst_name}->{+KEY_START_COMMAND}=$CFG::CFG{+KEY_INSTANCES}{$inst_name}{+KEY_START_COMMAND};
    } else {
      next; #
    }
    
    # pid file
    if($CFG::CFG{+KEY_INSTANCES}{$inst_name}{+KEY_PID_FILE}) {
      $workmap->{$inst_name}->{+KEY_PID_FILE}=$CFG::CFG{+KEY_INSTANCES}{$inst_name}{+KEY_PID_FILE};
    } else {
      next;
    }
    
    # heartbeat file
    if($CFG::CFG{+KEY_INSTANCES}{$inst_name}{+KEY_HEARTBEAT_FILE}) {
      $workmap->{$inst_name}->{+KEY_HEARTBEAT_FILE}=$CFG::CFG{+KEY_INSTANCES}{$inst_name}{+KEY_HEARTBEAT_FILE};
    } else {
      next;
    }
    
    # alive timeout
    if($CFG::CFG{+KEY_INSTANCES}{$inst_name}{+KEY_ALIVE_TIMEOUT}) { 
      $workmap->{$inst_name}->{+KEY_ALIVE_TIMEOUT}=$CFG::CFG{+KEY_INSTANCES}{$inst_name}{+KEY_ALIVE_TIMEOUT};
    } else {
      $workmap->{$inst_name}->{+KEY_ALIVE_TIMEOUT}=$default_alive_timeout;
    }
    # start timeout
    if($CFG::CFG{+KEY_INSTANCES}{$inst_name}{+KEY_START_TIMEOUT}) { 
      $workmap->{$inst_name}->{+KEY_START_TIMEOUT}=$CFG::CFG{+KEY_INSTANCES}{$inst_name}{+KEY_START_TIMEOUT};
    } else {
      $workmap->{$inst_name}->{+KEY_START_TIMEOUT}=$default_start_timeout;
    }
    # dead timeout
    if($CFG::CFG{+KEY_INSTANCES}{$inst_name}{+KEY_TERM_TIMEOUT}) { 
      $workmap->{$inst_name}->{+KEY_TERM_TIMEOUT}=$CFG::CFG{+KEY_INSTANCES}{$inst_name}{+KEY_TERM_TIMEOUT};
    } else {
      $workmap->{$inst_name}->{+KEY_TERM_TIMEOUT}=$default_term_timeout;
    }
    
    # wait
    if($CFG::CFG{+KEY_INSTANCES}{$inst_name}{+KEY_WAIT_BEFORE_NEXT}) { 
      $workmap->{$inst_name}->{+KEY_WAIT_BEFORE_NEXT}=$CFG::CFG{+KEY_INSTANCES}{$inst_name}{+KEY_WAIT_BEFORE_NEXT};
    } else {
      $workmap->{$inst_name}->{+KEY_WAIT_BEFORE_NEXT}=0;
    }
    
    #if($CFG::CFG{+KEY_INSTANCES}{$inst_name}{'user'}) {
    #  $workmap->{$inst_name}->{'user'}=$CFG::CFG{+KEY_INSTANCES}{$inst_name}{'user'};
    #}
    #if($CFG::CFG{+KEY_INSTANCES}{$inst_name}{'password'}) {
    #  $workmap->{$inst_name}->{'password'}=$CFG::CFG{+KEY_INSTANCES}{$inst_name}{'password'};
    #}
        
    # state initialized
    $workmap->{$inst_name}->{+KEY_STATE}=STATE_INIT;
    
} continue {
    dumpInstanceData($workmap->{$inst_name});
}

logV(4, "watchdog initialized. starting instances \n\n");

my $cntValideInstances = 0;
# process instances loop 
do {
  $cntValideInstances = 0;
  foreach my $inst_name (@{$instList})   {
    logV(4, "check instance: ".$inst_name."\n");
    processInstance($workmap->{$inst_name});
  }
  logV(4, "count valide instances: ".$cntValideInstances."\n");
  if($cntValideInstances == 0) {
    logV(4,"no valide instances to watch. exiting...\n");
    $sig_term=1;
  } else {
    sleep($check_interval);
  }
} until($sig_term);

if($pidFile) {
  logV(5,"delete PID\n");
  deleteFile($pidFile);
}
logV(4,"\nwatchdog terminated\n");

exit(0);

# processing
sub processInstance($) {
    my $inst = $_[0];
    
    my $state = $inst->{+KEY_STATE};
    if($state eq STATE_INVALIDE) { return -1; }
    $cntValideInstances++;
    
    my $pid_file = $inst->{+KEY_PID_FILE};
    my $hb_file = $inst->{+KEY_HEARTBEAT_FILE};
    my $pid = $inst->{+KEY_PID};
    
    #test
    #$inst->{+KEY_STATE} = STATE_STARTING;
    #if(checkStartTimeout($inst)) {
    #  logV(5,"Timeout!\n");
    #}
    #checkHBFile("/var/run/fhem/fhem_test.pid",60);
    
    #
    # INIT     -> pidf exist? + process exist? + hbf exist? -> ALIVE (suspicious)
    #             pidf exist? + process exist? + -          -> TARGET_ERROR
    #             pidf exist? + ^ (delete pidf, delete hbf) -> self
    #             ^               (delete hbf, waitBeforeTime? start)-> STARTING
    #                                          ^            -> self
    #
    # TARGET_ERROR                                          -> self
    #
    # ALIVE    -> pidf exist? + pidf actual(!aliveTimeout)? -> self
    #             pidf exist? + ^                           -> DEAD
    #             ^                                         -> TERMINATED
    #           
    # DEAD     -> (sig term)                                -> AWAITING_DEATH
    #
    # AWAITING_DEATH -> timeout? -> (sig kill)              -> TERMINATED
    #                   ^                                   -> self
    #
    # TERMINATED -> INIT
    # 
    # STARTING -> pidf exist? + pidf actual (!startTimeout)?-> ALIVE
    #             startTimeout?                             -> DEAD
    #             ^                                         -> self
    # 
    #
    
    if($state eq +STATE_INIT) {
      #STATE_INIT
      # if(exist pidf)
      #   if(exist proc)
      #     if(exist hbf) => ALIVE
      #     else => TARGET_ERROR
      #   else delete pdf (delete hbf if any) =>self
      # else if(checkWaitBeforeTime) => startProg($inst) => $state = +STARTING;
      # 
      #logV(5, " - state INIT\n");
      if(checkPidFile($pid_file)) {
        #logV(5, " -- pid file exist\n");
        $pid = readPid($pid_file) if (!defined($pid));
        if(checkPid($pid)) {
          #if(checkFileExist($hb_file)) {
          if(!checkAliveTimeout($inst)) {
            setStatus($inst, +STATE_ALIVE);
          } else {
            #setStatus($inst, +STATE_TARGET_ERROR);
            setStatus($inst, +STATE_STARTING);
          }
        } else {
          deleteFile($pid_file);
          if(checkFileExist($hb_file)) {
            deleteFile($hb_file);
          }
        }
      } elsif (checkWaitBeforeTime($inst)){
        logV(5, " -- start proc\n");
        startProg($inst);
        $lastStartTime = getCurrentTime();
        setStatus($inst, +STATE_STARTING);
      } else {
        logV(5, " -- wait for starting prev proc\n");
      }
    } elsif ($state eq +STATE_INVALIDE) {
      #STATE_INVALIDE
      #IGNORED (invalide configuration or program error)
    } elsif ($state eq +STATE_TARGET_ERROR) {
      #TARGET_ERROR
      #IGNORED (target misconfigured)
    } elsif ($state eq +STATE_STARTING) {
      #STATE_STARTING
      #if(checkPidFile($pid_file)) {
      #  setStatus($inst, +STATE_ALIVE);
      #} elsif (!checkStartTimeout($inst)) {
      #    setStatus($inst, +STATE_DEAD);
      #}
      my $pid_ok = 0;
      if(checkPidFile($pid_file)) {
        $pid = readPid($pid_file) if (!defined($pid)); 
        if(checkPid($pid)) {
          $pid_ok = 1;
        }
      }
      if(!checkStartTimeout($inst)) {
      #logV(5,"T!\n");
        if(!checkAliveTimeout($inst)) {
          setStatus($inst, +STATE_ALIVE);
        }
      } else {
        if($pid_ok) {
          if(checkFileExist($hb_file)) {
            setStatus($inst, +STATE_ALIVE);
          } else {
            setStatus($inst, +STATE_TARGET_ERROR);
          }
        } else {
          setStatus($inst, +STATE_DEAD);
        }
      }
    } elsif ($state eq +STATE_ALIVE) {
      #STATE_ALIVE
      if(checkPidFile($pid_file)) {
        $pid = readPid($pid_file) if (!defined($pid));
        if(checkPid($pid)) {
          if(checkAliveTimeout($inst)) {
            setStatus($inst, +STATE_DEAD);
          }
        } else {
          deleteFile($pid_file);
          setStatus($inst, +STATE_TERMINATED);
        }
      } else {
        setStatus($inst, +STATE_TERMINATED);
      }
    } elsif ($state eq +STATE_DEAD) {
      #STATE_DEAD
      if(checkPidFile($pid_file)) {
        $pid = readPid($pid_file) if (!defined($pid));
        #todo process pruefen
        logV(5, "kill process (SIGTERM) PID: ".$pid."\n");
        kill 15, $pid; # SIGTERM
        setStatus($inst, +STATE_AWAITING_DEATH);
      } else {
        #TODO: PID unbekannt, was nun?
        setStatus($inst, +STATE_INVALIDE);
      }
    } elsif ($state eq +STATE_AWAITING_DEATH) {
      #STATE_AWAITING_DEATH
      #if(checkPidFile($pid_file)) {
      #  $pid = readPid($pid_file) if (!defined($pid));
      if(!defined($pid)) {
        logV(2,"undefined pid. probable inernal error\n");
        setStatus($inst, +STATE_INVALIDE);
      } elsif (checkPid($pid)) {
        #todo process pruefen
        if(checkTermTimeout($inst)) {
          logV(5, "kill process (SIGKILL) PID: ".$pid."\n");
          kill 9, $pid; # SIGKILL
          deleteFile($pid_file);
          setStatus($inst, +STATE_TERMINATED);
         }
      } else {
        setStatus($inst, +STATE_TERMINATED);
      }
    } elsif ($state eq +STATE_TERMINATED) {
      #STATE_TERMINATED
      setStatus($inst, +STATE_INIT);
      $pid = undef;
      $inst->{+KEY_PID} = undef;
    } else {
      # ERROR (unknown state)
      logV(2,"unknown state: ".$state."\n");
      setStatus($inst, +STATE_INVALIDE);
    }
    
    $inst->{+KEY_PID} = $pid;
    
    # TEST/DEBUG
    #logV(4," -> check instance: ".$pid_file." state: ".$inst->{+KEY_STATE}."\n");
    logV(4,"state: ".$inst->{+KEY_STATE}."\n");
    # TEST
    # check PID-File
    #if (-e $pid_file) {
    if(checkPidFile($pid_file)) {
      logV(4,"    PID found \n");
    } else {
      logV(4,"    PID not found \n");
    }
}

# --- utils ------------------------------------
#
# Read a configuration file (s. http://www.perlmonks.org/?node_id=464358)
#   The arg can be a relative or full path, or
#   it can be a file located somewhere in @INC.
sub readCfg ($) {
    my $file = $_[0];

    our $err;

    {   # Put config data into a separate namespace
        package CFG;

        # Process the contents of the config file
        my $rc = do($file);

        # Check for errors
        if ($@) {
            $::err = "ERROR: Failure compiling '$file' - $@";
        } elsif (! defined($rc)) {
            $::err = "ERROR: Failure reading '$file' - $!";
        } elsif (! $rc) {
            $::err = "ERROR: Failure processing '$file'";
        }
    }

    return ($err);
}

sub signalHandling() {
  if($^O ne "MSWin32") {
    $SIG{TERM} =  sub { $sig_term = 1; }; #
    $SIG{INT} =   sub { $sig_term = 1; }; # Ctrl+C
    $SIG{PIPE} = 'IGNORE';
    $SIG{CHLD} = 'IGNORE';
    $SIG{HUP}  = 'IGNORE';
    $SIG{TSTP}  = 'IGNORE'; # Ctrl+Z
    #$SIG{ALRM} = sub {...};
  }
  # $SIG{__WARN__} = sub {...}
  # $SIG{__DIE__} = sub {...}
}

sub isVerbose($) {
  my $vl = $_[0];
  return $verbose >= $vl;
}

sub logV($$) {
  my ($level, $msg) = @_;
  print(STDOUT $msg) if isVerbose($level);
}

sub getCurrentTime() {
  return int(time());
}

sub dumpInstanceData($) {
  my ($map) = @_;
  logV(5,'     state:           '.$map->{+KEY_STATE}."\n");
  logV(5,'     duration:        '.(getCurrentTime()-$map->{+KEY_TIMESTAMP})."\n");
  logV(5,'     base dir:        '.$map->{+KEY_BASE_DIR}."\n") if $map->{+KEY_BASE_DIR};
  logV(5,'     pid file:        '.$map->{+KEY_PID_FILE}."\n") if $map->{+KEY_PID_FILE};
  logV(5,'     heartrbeat file: '.$map->{+KEY_HEARTBEAT_FILE}."\n") if $map->{+KEY_HEARTBEAT_FILE};
  logV(5,'     start command:   '.$map->{+KEY_START_COMMAND}."\n") if $map->{+KEY_START_COMMAND};
  logV(5,'     alive timeout:   '.$map->{+KEY_ALIVE_TIMEOUT}."\n") if $map->{+KEY_ALIVE_TIMEOUT};
  logV(5,'     start timeout:   '.$map->{+KEY_START_TIMEOUT}."\n") if $map->{+KEY_START_TIMEOUT};
  logV(5,'     term timeout:    '.$map->{+KEY_TERM_TIMEOUT}."\n") if $map->{+KEY_TERM_TIMEOUT};
  logV(5,'     wait before next:'.$map->{+KEY_WAIT_BEFORE_NEXT}."\n") if $map->{+KEY_WAIT_BEFORE_NEXT};
}

sub setStatus($$) {
  my ($map, $state) = @_;
  logV(4,"next state: ".$map->{+KEY_STATE}." => ".$state."\n");
  $map->{+KEY_STATE} = $state;
  $map->{+KEY_TIMESTAMP} = getCurrentTime();
}

sub startProg($) {
  my ($map) = @_;
  logV(5, "starting: ".$map->{+KEY_START_COMMAND}."\n");
  #system("cd ".$map->{+KEY_BASE_DIR}."; ".$map->{+KEY_START_COMMAND});
  chdir($map->{+KEY_BASE_DIR}) or logV(1, "Error changing directory to ".$map->{+KEY_BASE_DIR}.":$! \n" );
  #system($map->{+KEY_START_COMMAND}." &");
  #my $cmd = $map->{+KEY_START_COMMAND}." &";
  #logV(5,`$cmd`);
  #my $pid = open my $fhOut, "| ".$map->{+KEY_START_COMMAND}." &";
  #logV(5, "=> pid ".$pid."\n");
  
  my $pid = fork();
	if(!defined $pid) {
		logV(1,"Could not fork!\n");
	} elsif($pid == 0) {
		#Hier bin ich im Child-Prozess
		logV(5,"starting: ".$map->{+KEY_START_COMMAND}."\n");
		# sitsid ist wichtig um den Prozess von dem Vater abzukoppeln. 
		# Dabei wird der Kindprozess auch nicht mehr beim Beenden des Vaters mit Ctrl-C beendet.
		if (setsid() == -1) {
		  logV(1,"Could not setid\n");
		}
		#logV(5,"-----------------: ".$$."\n");
		exec($map->{+KEY_START_COMMAND});
	} else {
		#Hier bin ich im Parent-Prozess
		#logV(5,"proc started with pid: $pid\n");
	}
  
}

sub checkPid($) {
  my ($pid) = @_;
  if(looks_like_number($pid)) {
    logV(5, "check PID: ".$pid."\n");
    my $exists = kill 0, $pid;
    return $exists;
  } else {
    logV(5, "check PID: not a number! ".$pid."\n");
  }
  return 0;
}

sub readPid($) {
  my ($pfn) = @_;
  if($pfn) {
    logV(1,"could not read $pfn: $!\n") if(!open(PID, "<$pfn"));
    my $firstLine = <PID>;
    close(PID);
    return $firstLine;
  }
}

sub checkAliveTimeout($) {
  my ($map) = @_;
  my $state = $map->{+KEY_STATE};
  #if($state ne +STATE_ALIVE) {
  #  return -1;
  #}
  
  return !checkHBFile($map->{+KEY_HEARTBEAT_FILE},$map->{+KEY_ALIVE_TIMEOUT});
  ##my $ctime = getCurrentTime();
  #my $etime = $map->{+KEY_TIMESTAMP};
  #my $timeout = $map->{+KEY_ALIVE_TIMEOUT};
  ##if(($ctime-$etime) <= $timeout) {
  ##  return 0;
  ##}
  ##return 1;
  #return checkTimeout($etime, $timeout);
}

sub checkStartTimeout($) {
  my ($map) = @_;
  my $state = $map->{+KEY_STATE};
  if($state ne +STATE_STARTING) {
    return -1;
  }
  #my $ctime = getCurrentTime();
  my $etime = $map->{+KEY_TIMESTAMP};
  my $timeout = $map->{+KEY_START_TIMEOUT};
  #if(($ctime-$etime) <= $timeout) {
  #  return 0;
  #}
  #return 1;
  return checkTimeout($etime, $timeout);
}

sub checkTermTimeout($) {
  my ($map) = @_;
  my $state = $map->{+KEY_STATE};
  if($state ne +STATE_AWAITING_DEATH) {
    return -1;
  }
  #my $ctime = getCurrentTime();
  my $etime = $map->{+KEY_TIMESTAMP};
  my $timeout = $map->{+KEY_TERM_TIMEOUT};
  #if(($ctime-$etime) <= $timeout) {
  #  return 0;
  #}
  #return 1;
  return checkTimeout($etime, $timeout);
}

sub checkTimeout($$) {
  my ($etime,$timeout) = @_;
  my $ctime = getCurrentTime();
  #logV(5, "time: ".($ctime-$etime)."\n");
  if(($ctime-$etime) <= $timeout) {
    return 0;
  }
  return 1;
}

sub checkWaitBeforeTime($) {
  my ($map) = @_;
  my $timeout = $map->{+KEY_WAIT_BEFORE_NEXT};
  return checkTimeout($lastStartTime, $timeout);
}

sub checkFileExist($) {
  my ($fln) = @_;
  #return -1 unless $fln;
  return 0 unless $fln;
  if (-e $fln) {
    return 1;
  } 
  return 0;
}

sub checkPidFile($) {
  my ($pfn) = @_;
  return checkFileExist($pfn);
}

sub checkHBFile($$) {
  my ($fln, $timeout) = @_;
  #return -1 unless $pfn;
  logV(5, "--checkHBFile: undef\n")unless $fln;
  return 0 unless $fln;
  
  logV(5, "--checkHBFile: ".$fln." => ");
  if (checkFileExist($fln)) {
    my $ctime = getCurrentTime();
    # check file timestamp 
    my $wtime = (stat($fln))[9]; # 9 is a magic number s. stat functionfor another
    logV(5, " [time: ".($ctime-$wtime).", timeout: $timeout] ");
    if(($ctime-$wtime) <= $timeout) {
      logV(5, "1\n");
      return 1;
    }
    logV(5, "0\n");
    return 0;
  }
  logV(5, "[not found] 0\n");
  return 0;
}

sub checkAnotherInstancePid($) {
  # TODO: Prüfen, ob bereits mit der gleichen Konfiguration läuft
}

sub createPidFile($) {
  my ($pfn) = @_;
  if($pfn) {
    die "$pfn: $!\n" if(!open(PID, ">$pfn"));
    print PID $$ . "\n";
    close(PID);
  }
}

sub deleteFile($) {
  my ($fln) = @_;
  logV(5, "delete: $fln\n");
  unlink($fln) if($fln);
}
