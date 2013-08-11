/* 
   LoginWindow.h

   Class to allow the display of a borderless window.  It also
   provides the necessary functionality for some of the other nice
   things we want the window to do.

   Copyright (C) 2000 Free Software Foundation, Inc.

   Author:  Gregory John Casamento <greg_casamento@yahoo.com>
   Date: 2000
   
   This file is part of GNUstep.

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

   You can reach me at:
   Gregory Casamento, 14218 Oxford Drive, Laurel, MD 20707, 
   USA
*/

#import <AppKit/AppKit.h>

@interface LoginWindow : NSWindow
{
    IBOutlet NSTextField  *hostnameText;
    IBOutlet NSImageView  *loginImageView;
    IBOutlet NSTextView   *passwordText;
    IBOutlet NSButton     *powerButton;
    IBOutlet NSButton     *restartButton;
    IBOutlet NSTextField  *usernameText;
    
    /** to remember original rect before shrinking */
    NSRect savedWindowRect;
}
- (void)initializeInterface;
- (void)displayPanel;
- (void)displayPowerButton;
- (void)displayRestartButton;
- (void)displayHostname;
- (void)waggle;
- (void)shrink;
- (void)restore;
@end
