/* 
   Authenticator.m

   Class to allow loginpanel to authenticate users

   Copyright (C) 2013 Lucas Holt

   Copyright (C) 2000-2013 GNUstep Application Project

   Author:  Gregory John Casamento <borgheron@yahoo.com>
   Date: 2000
   Author: Riccardo Mottola <rmottola@users.sf.net>
   
   This file is part of loginpanel, GNUstep Application Project

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.
   
   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this library; see the file COPYING.LIB.
   If not, write to the Free Software Foundation,
   59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* Authenticator.m created by me on Wed 17-Nov-1999 */

#import "Authenticator.h"

/* needed on linux to get crypt from unistd */
#ifdef __linux__
#define _XOPEN_SOURCE
#endif

#include <sys/types.h>
#include <unistd.h>
#include <signal.h>

#include <grp.h>

#ifdef __MidnightBSD_version
#include <login_cap.h>
#include <security/openpam.h>
#include <syslog.h>
#include <stdarg.h>
#include <pwd.h>
#include <sys/time.h>
#include <sys/resource.h>
#endif

#if HAVE_OPENBSD_AUTH
#include <login_cap.h>
#include <bsd_auth.h>
#endif


@implementation Authenticator
// Initialization methods
- (id)init
{
  [super init];
  NSLog(@"Initing authenticator");
  username = nil;
  password = nil;
#if defined(HAVE_PAM) || defined(__MidnightBSD_version)
  pamc.conv = &openpam_ttyconv;
  pam_silent = PAM_SILENT;
#endif
#ifdef __linux__
  passwordFilePath = @"/etc/shadow";
#else 
  passwordFilePath = @"/etc/master.passwd";
#endif
  return self;
}

- initWithUsername: (NSString *)user
          password: (NSString *)pass
{
  [self init];
  username = [user copy];
  password = [pass copy];
  return self;
}

- (void)_readLine :(FILE *)f :(char *)l
{
    int ch;
    
    ch = fgetc(f);
    while (ch != EOF && ch != '\n')
    {
        *l = ch;
        l++;
        ch = fgetc(f);
    }
    *l = '\0';
}

// Accessor methods
- (void)setUsername: (NSString *)user
{
  username = user;
}

- (void)setPassword: (NSString *)pass
{
  password = pass;
}

- (NSString *)username
{
  return username;
}

- (NSString *)password
{
  return password;
}

- (struct passwd *)getPasswordEntity
{
  return pw;
}


/** perform the actual password verification */
- (BOOL)isPasswordCorrect
{
  NSLog(@"Verifying... %@", username);

#ifdef __MidnightBSD_version
  BOOL ret;
  int rval;
  char hostname[MAXHOSTNAMELEN];
  const char *tty;

  NSLog(@"MidnightBSD code path");

  pw = getpwnam([username cString]);
  pam_err = pam_start("su", [username cString], &pamc, &handle);
  if (pam_err != PAM_SUCCESS) {
    [self pamSyslog: @"pam_start()"];
#ifdef USE_BSM_AUDIT
    au_login_fail("PAM Error", 1);
#endif
    return NO;
  }

  gethostname(hostname, sizeof(hostname));
  if ((pam_err = pam_set_item(handle, PAM_RHOST, hostname)) != PAM_SUCCESS) {
    [self pamSyslog: @"set hostname"];
    return NO;
  }
  /* PAM_RUSER ? */
  pam_set_item(handle, PAM_RHOST, getlogin());
  tty = ttyname(STDERR_FILENO);
  if ((pam_err = pam_set_item(handle, PAM_TTY, tty)) != PAM_SUCCESS) {
    [self pamSyslog: @"set tty"];
    return NO;
  }
  
  NSLog(@"pamAuth()");
  (void)setpriority(PRIO_PROCESS, 0, -4);
  rval = [self pamAuth];
  (void)setpriority(PRIO_PROCESS, 0, 0);
  NSLog(@"pamCleanup");
  [self pamCleanup];

  if (pw && rval == 0)
    ret = YES;

  return ret;
#endif

#if HAVE_OPENBSD_AUTH
  BOOL ret;

  ret = (BOOL)auth_userokay((char *)[username cStringUsingEncoding:NSUTF8StringEncoding] ,NULL,NULL,
			(char *)[password cStringUsingEncoding:NSUTF8StringEncoding]);  
  pw = getpwnam([username cString]);
  return ret;
#endif


  if(YES)  // we should do this if we have a master password file
    {
      NSString *pwdFileStr;
      NSEnumerator *enu;
      NSArray *usersArray;
      NSString *userLine;
      NSString *userNameWithColon;
      unsigned int userNameLen;
      NSString *cryptedPwdFromFile;

      userNameWithColon = [username stringByAppendingString:@":"];
      userNameLen = [userNameWithColon length];
      //      NSLog(@"password: %@", password);

      pwdFileStr = [NSString stringWithContentsOfFile:passwordFilePath];
      if ([pwdFileStr length] == 0)
        NSLog(@"Empty password file");
      usersArray = [pwdFileStr componentsSeparatedByString:@"\n"];
      cryptedPwdFromFile = nil;
      enu = [usersArray objectEnumerator];
      while((userLine = [enu nextObject]) && cryptedPwdFromFile == nil)
        {
	  //	  NSLog(@"line %@", userLine);
	  if ([userLine length] > userNameLen)
	    {
	     if ([userLine compare: userNameWithColon options:NSLiteralSearch
	      range:NSMakeRange(0, userNameLen)] == NSOrderedSame)
	        {
		  NSArray *pwdLineArray;
	          NSLog(@"found %@", userLine);
                  pwdLineArray = [userLine componentsSeparatedByString:@":"];
		  cryptedPwdFromFile = [pwdLineArray objectAtIndex:1];
	        }
            }
	}

	if (cryptedPwdFromFile != nil)
	{
	  unsigned int saltEnd;
	  
	  NSLog(@"pass from file: %@", cryptedPwdFromFile);
	  saltEnd = 3;
	  while (saltEnd < [cryptedPwdFromFile length] && [cryptedPwdFromFile
	  characterAtIndex:saltEnd] != '$')
	    saltEnd++;
	  if (saltEnd < [cryptedPwdFromFile length])
	    {
	      NSString *salt;
	      NSString *recrypted;
	      
	      salt = [cryptedPwdFromFile substringFromRange:NSMakeRange(0, saltEnd)];
	      NSLog(@"Salt: %@", salt);
	      recrypted = [NSString stringWithCString:crypt([password cString],
	      [salt cString])];
	      NSLog(@"recrypted: %@", recrypted);
	      if ([recrypted compare:cryptedPwdFromFile options:NSLiteralSearch] == NSOrderedSame)
	        {
		  NSLog(@"Equal");
		  pw = getpwnam([username cString]);
		  return YES;
		}
		else
	        {
		  NSLog(@"Not Equal");
		  return NO;
		}
	    }
	    else
	    {
	      NSLog(@"error, no salt found in password");
	      return NO;
	    }
	}
    }
  return NO;
}

- (void)setEnvironment
{
  chdir(pw->pw_dir);
}

#if defined(__MidnightBSD_version)

- (void)pamSyslog: (NSString *)message
{
  NSLog(@"syslog: %@", message);
  //syslog(LOG_ERR, "%s : %s", [message cString], pam_strerror(handle, pam_err));
}

- (void)pamCleanup
{
        if (handle != NULL) {
                if (pam_session_established) {
                        pam_err = pam_close_session(handle, 0);
                        if (pam_err != PAM_SUCCESS)
				[self pamSyslog: @"pam_close_session()"];
                }
                pam_session_established = 0;
                if (pam_cred_established) {
                        pam_err = pam_setcred(handle, pam_silent|PAM_DELETE_CRED);
                        if (pam_err != PAM_SUCCESS)
                                [self pamSyslog: @"pam_setcred()"];
                }
                pam_cred_established = 0;
                pam_end(handle, pam_err);
                handle = NULL;
        }
}

/*
 * Attempt to authenticate the user using PAM.  Returns 0 if the user is
 * authenticated, or 1 if not authenticated.  If some sort of PAM system
 * error occurs (e.g., the "/etc/pam.conf" file is missing) then this
 * function returns -1.  This can be used as an indication that we should
 * fall back to a different authentication mechanism.
 */
- (int)pamAuth
{
        const char *tmpl_user;
        const void *item;
        int rval;

	NSLog(@"In pamAuth()");

        pam_err = pam_authenticate(handle, 0); // pam_silent
NSLog(@"made it after pam_authentiate");
        switch (pam_err) {

        case PAM_SUCCESS:
                /*
                 * With PAM we support the concept of a "template"
                 * user.  The user enters a login name which is
                 * authenticated by PAM, usually via a remote service
                 * such as RADIUS or TACACS+.  If authentication
                 * succeeds, a different but related "template" name
                 * is used for setting the credentials, shell, and
                 * home directory.  The name the user enters need only
                 * exist on the remote authentication server, but the
                 * template name must be present in the local password
                 * database.
                 *
                 * This is supported by two various mechanisms in the
                 * individual modules.  However, from the application's
                 * point of view, the template user is always passed
                 * back as a changed value of the PAM_USER item.
                 */
		NSLog(@"pam_get_item()");
                pam_err = pam_get_item(handle, PAM_USER, &item);
                if (pam_err == PAM_SUCCESS) {
                        tmpl_user = (const char *)item;
			NSLog(@"Template user %s", tmpl_user);
                        if (strcmp([username cString], tmpl_user) != 0)
                                pw = getpwnam(tmpl_user);
                } else {
                        [self pamSyslog: @"pam_get_item(PAM_USER)"];

		}
                rval = 0;
                break;

        case PAM_AUTH_ERR:
        case PAM_USER_UNKNOWN:
        case PAM_MAXTRIES:
                rval = 1;
                break;

        default:
                [self pamSyslog: @"pam_authenticate()"];
                rval = -1;
                break;
        }

        if (rval == 0) {
		NSLog(@"pam_acct_mgmt call");
                pam_err = pam_acct_mgmt(handle, pam_silent);
                switch (pam_err) {
                case PAM_SUCCESS:
                        break;
                case PAM_NEW_AUTHTOK_REQD:
                        pam_err = pam_chauthtok(handle,
                            pam_silent|PAM_CHANGE_EXPIRED_AUTHTOK);
                        if (pam_err != PAM_SUCCESS) {
                                [self pamSyslog: @"pam_chauthtok()"];
                                rval = 1;
                        }
                        break;
                default:
                        [self pamSyslog: @"pam_acct_mgmt()"];
                        rval = 1;
                        break;
                }
        }

        if (rval != 0) {
                pam_end(handle, pam_err);
                handle = NULL;
        }
        return (rval);
}

#endif

@end
