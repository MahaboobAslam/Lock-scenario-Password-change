//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
// This file contains some global variables that describe what our
// sample tile looks like.  For example, it defines what fields a tile has
// and which fields show in which states of LogonUI. This sample illustrates
// the use of each UI field type.

#pragma once
#include "helpers.h"

// The indexes of each of the fields in our credential provider's tiles. Note that we're
// using each of the nine available field types here.
enum SAMPLE_FIELD_ID
{
    SFI_TILEIMAGE         = 0,
    SFI_USERNAMELABLE = 1,
    SFI_LABEL             = 2,
    SFI_LOGIN_NAME = 3,
    SFI_LARGE_TEXT        = 4,
    SFI_PASSWORD          = 5,
    SFI_SUBMIT_BUTTON     = 6,
    SFI_DOMAIN_NAME_TEXT = 7,
    SFI_OLDPASSWORD_TEXT = 8,
    SFI_OLDPASSWORD = 9,
    SFI_NEWPASSWORD_TEXT = 10,
    SFI_NEWPASSWORD = 11,
    SFI_CONFPASSWORD_TEXT = 12,
    SFI_CONFPASSWORD = 13,
   /* SFI_LAUNCHWINDOW_LINK = 5,
    SFI_HIDECONTROLS_LINK = 6,
    SFI_FULLNAME_TEXT     = 7,
    SFI_DISPLAYNAME_TEXT  = 8,
    SFI_LOGONSTATUS_TEXT  = 9,
    SFI_CHECKBOX          = 10,
    SFI_EDIT_TEXT         = 11,
    SFI_COMBOBOX          = 12,*/
    SFI_NUM_FIELDS        = 14,  // Note: if new fields are added, keep NUM_FIELDS last.  This is used as a count of the number of fields
};

// The first value indicates when the tile is displayed (selected, not selected)
// the second indicates things like whether the field is enabled, whether it has key focus, etc.
struct FIELD_STATE_PAIR
{
    CREDENTIAL_PROVIDER_FIELD_STATE cpfs;
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis;
};

// These two arrays are seperate because a credential provider might
// want to set up a credential with various combinations of field state pairs
// and field descriptors.

// The field state value indicates whether the field is displayed
// in the selected tile, the deselected tile, or both.
// The Field interactive state indicates when


//static const FIELD_STATE_PAIR s_rgFieldStatePairs[] =
//{
//    { CPFS_DISPLAY_IN_BOTH,            CPFIS_NONE    },    // SFI_TILEIMAGE
//    { CPFS_HIDDEN,                     CPFIS_NONE    },    // SFI_LABEL
//    { CPFS_DISPLAY_IN_BOTH,            CPFIS_NONE    },    // SFI_LARGE_TEXT
//    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_FOCUSED },    // SFI_PASSWORD
//    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_SUBMIT_BUTTON
//    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_LAUNCHWINDOW_LINK
//    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_HIDECONTROLS_LINK
//    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_FULLNAME_TEXT
//    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_DISPLAYNAME_TEXT
//    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_LOGONSTATUS_TEXT
//    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_CHECKBOX
//    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_EDIT_TEXT
//    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_COMBOBOX
//};

static const FIELD_STATE_PAIR s_rgFieldStatePairs[] =
{
    { CPFS_DISPLAY_IN_BOTH,            CPFIS_NONE    },    // SFI_TILEIMAGE
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    //SFI_USERNAMELABLE
    { CPFS_HIDDEN,                     CPFIS_NONE    },    // SFI_LABEL
    { /*CPFS_DISPLAY_IN_SELECTED_TILE*/ CPFS_HIDDEN,					   CPFIS_NONE	 },		//SFI_LOGIN_NAME
    { CPFS_HIDDEN,					   CPFIS_NONE	 },    // SFI_LARGE_TEXT
    /*{ CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_FOCUSED },    // SFI_EDIT_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_OKAY_BUTTON*/
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_FOCUSED },    // SFI_PASSWORD
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_SUBMIT_BUTTON
    { CPFS_DISPLAY_IN_SELECTED_TILE,					   CPFIS_NONE    },    // SFI_RESETPSW_LINK
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },//SFI_DOMAIN_NAME_TEXT
    /*{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },    // SFI_CHANGEPSW_LINK
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },    // SFI_UNLOCKACCT_LINK
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_DISPLAYNAME_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_LOGONSTATUS_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_CHECKBOX
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_COMBOBOX
    */
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_OLDPASSWORD_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_OLDPASSWORD
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_NEWPASSWORD_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_FOCUSED /*CPFIS_NONE*/    },    // SFI_NEWPASSWORD
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_CONFPASSWORD_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_CONFPASSWORD 
 //   { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    }     // SFI_NEWPSSWRD
    /*{ CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_DUMMY_LINK*/
};

// Field descriptors for unlock and logon.
// The first field is the index of the field.
// The second is the type of the field.
// The third is the name of the field, NOT the value which will appear in the field.
//static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgCredProvFieldDescriptors[] =
//{
//    { SFI_TILEIMAGE,         CPFT_TILE_IMAGE,    L"Image",                      CPFG_CREDENTIAL_PROVIDER_LOGO  },
//    { SFI_LABEL,             CPFT_SMALL_TEXT,    L"Tooltip",                    CPFG_CREDENTIAL_PROVIDER_LABEL },
//    { SFI_LARGE_TEXT,        CPFT_EDIT_TEXT/*CPFT_LARGE_TEXT*/,    L"Sample Credential Provider"                                 },
//    { SFI_PASSWORD,          CPFT_PASSWORD_TEXT, L"Password text"                                              },
//    { SFI_SUBMIT_BUTTON,     CPFT_SUBMIT_BUTTON, L"Submit"                                                     },
//    { SFI_LAUNCHWINDOW_LINK, CPFT_COMMAND_LINK,  L"Launch helper window"                                       },
//    { SFI_HIDECONTROLS_LINK, CPFT_COMMAND_LINK,  L"Hide additional controls"                                   },
//    { SFI_FULLNAME_TEXT,     CPFT_SMALL_TEXT,    L"Full name: "                                                },
//    { SFI_DISPLAYNAME_TEXT,  CPFT_SMALL_TEXT,    L"Display name: "                                             },
//    { SFI_LOGONSTATUS_TEXT,  CPFT_SMALL_TEXT,    L"Logon status: "                                             },
//    { SFI_CHECKBOX,          CPFT_CHECKBOX,      L"Checkbox"                                                   },
//    { SFI_EDIT_TEXT,         CPFT_EDIT_TEXT,     L"Edit text"                                                  },
//    { SFI_COMBOBOX,          CPFT_COMBOBOX,      L"Combobox"                                                    },
//};


static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgCredProvFieldDescriptors[] =
{
    { SFI_TILEIMAGE,         CPFT_TILE_IMAGE,    L"Image",                      CPFG_CREDENTIAL_PROVIDER_LOGO  },
    { SFI_USERNAMELABLE,     CPFT_LARGE_TEXT,    L""                                                            },
    { SFI_LABEL,             CPFT_SMALL_TEXT,    L"TecMFA",                   CPFG_CREDENTIAL_PROVIDER_LABEL },
    { SFI_LOGIN_NAME,        CPFT_EDIT_TEXT,     L"Login name"                                                 },
    { SFI_LARGE_TEXT,        CPFT_SMALL_TEXT,    L"TECNICS MFA"                                              },
    /*{ SFI_EDIT_TEXT,         CPFT_EDIT_TEXT,     L""                                                           },
    { SFI_OKAY_BUTTON,       CPFT_SUBMIT_BUTTON,  L""                                                          },*/
    { SFI_PASSWORD,          CPFT_PASSWORD_TEXT, L"Password"                                                   },
    { SFI_SUBMIT_BUTTON,     CPFT_SUBMIT_BUTTON, L""                                                           },
   // { SFI_FORGOTPSW_LINK,	 CPFT_COMMAND_LINK,  L"Need help signing in?"											   },
    { SFI_DOMAIN_NAME_TEXT,     CPFT_SMALL_TEXT,    L"Sign in to: "                                                },
    /*{ SFI_CHANGEPSW_LINK,	 CPFT_COMMAND_LINK,  L"Change Password"											   },
    { SFI_UNLOCKACCT_LINK,	 CPFT_COMMAND_LINK,  L"Unlock Account"                                             },
    { SFI_DISPLAYNAME_TEXT,  CPFT_SMALL_TEXT,    L"Display Name"                                               },
    { SFI_LOGONSTATUS_TEXT,  CPFT_SMALL_TEXT,    L"LogOn Status"                                               },
    { SFI_CHECKBOX,          CPFT_CHECKBOX,      L"Checkbox"                                                   },
    { SFI_COMBOBOX,          CPFT_COMBOBOX,      L"Combobox"                                                   },*/
    { SFI_OLDPASSWORD_TEXT,  CPFT_SMALL_TEXT,    L"Enter Old Password"                                         },
    { SFI_OLDPASSWORD,       CPFT_PASSWORD_TEXT, L"Old Password"                                               },
    { SFI_NEWPASSWORD_TEXT,  CPFT_SMALL_TEXT,    L"Enter New Password"                                         },
    { SFI_NEWPASSWORD,       CPFT_PASSWORD_TEXT, L"New Password"                                               },
    { SFI_CONFPASSWORD_TEXT, CPFT_SMALL_TEXT,    L"Confirm New Password"                                       },
    { SFI_CONFPASSWORD,      CPFT_PASSWORD_TEXT, L"Confirm New Password"                                       },
   // { SFI_NEWPSSWRD,         CPFT_PASSWORD_TEXT, L"Confirm New PSSWRD"                                         },

    /*{ SFI_DUMMY_LINK,        CPFT_COMMAND_LINK,  L""														   },*/

};
static const PWSTR s_rgComboBoxStrings[] =
{
    L"First",
    L"Second",
    L"Third",
};
