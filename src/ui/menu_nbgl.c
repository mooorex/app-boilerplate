
/*****************************************************************************
 *   Ledger App Boilerplate.
 *   (c) 2020 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#ifdef HAVE_NBGL

#include "os.h"
#include "glyphs.h"
#include "nbgl_use_case.h"

#include "globals.h"
#include "menu.h"
#include "display.h"
#include "types.h"

//  -----------------------------------------------------------
//  ----------------------- HOME PAGE -------------------------
//  -----------------------------------------------------------

void app_quit(void) {
    // exit app here
    os_sched_exit(-1);
}

//  -----------------------------------------------------------
//  --------------------- SETTINGS MENU -----------------------
//  -----------------------------------------------------------
#define SETTING_INFO_NB 2
static const char* const INFO_TYPES[SETTING_INFO_NB] = {"Version", "Developer"};
static const char* const INFO_CONTENTS[SETTING_INFO_NB] = {APPVERSION, "Ledger"};

// settings switches definitions
enum { BLIND_SIGNNING_SWITCH_TOKEN = FIRST_USER_TOKEN };
enum { BLIND_SIGNNING_SWITCH_ID = 0, SETTINGS_SWITCHES_NB };

static nbgl_contentSwitch_t switches[SETTINGS_SWITCHES_NB] = {0};

static const nbgl_contentInfoList_t infoList = {
    .nbInfos = SETTING_INFO_NB,
    .infoTypes = INFO_TYPES,
    .infoContents = INFO_CONTENTS,
};

static uint8_t initSettingPage;
static void controls_callback(int token, uint8_t index, int page);

// settings menu definition
#define SETTING_CONTENTS_NB 1
static const nbgl_content_t contents[SETTING_CONTENTS_NB] = {
    {.type = SWITCHES_LIST,
     .content.switchesList.nbSwitches = SETTINGS_SWITCHES_NB,
     .content.switchesList.switches = switches,
     .contentActionCallback = controls_callback}};

static const nbgl_genericContents_t settingContents = {.callbackCallNeeded = false,
                                                       .contentsList = contents,
                                                       .nbContents = SETTING_CONTENTS_NB};

static void controls_callback(int token, uint8_t index, int page) {
    UNUSED(index);

    initSettingPage = page;

    uint8_t switch_value;
    if (token == BLIND_SIGNNING_SWITCH_TOKEN) {
        // Blind signing switch touched
        // toggle the switch value
        switch_value = !N_storage.blind_signed_allowed;
        switches[BLIND_SIGNNING_SWITCH_ID].initState = (nbgl_state_t) switch_value;
        // store the new setting value in NVM
        nvm_write((void*) &N_storage.blind_signed_allowed, &switch_value, 1);
    }
}

// home page definition
void ui_menu_main(void) {
    // Initialize switches data
    switches[BLIND_SIGNNING_SWITCH_ID].initState = (nbgl_state_t) N_storage.blind_signed_allowed;
    switches[BLIND_SIGNNING_SWITCH_ID].text = BLIND_SIGNING_SWITCH_TEXT;
    switches[BLIND_SIGNNING_SWITCH_ID].subText = BLIND_SIGNING_SWITCH_SUBTEXT;
    switches[BLIND_SIGNNING_SWITCH_ID].token = BLIND_SIGNNING_SWITCH_TOKEN;
    // switches[BLIND_SIGNNING_SWITCH_ID].tuneId = TUNE_TAP_CASUAL;

    nbgl_useCaseHomeAndSettings(APPNAME,
                                &ICON_APP_ONTOLOGY,
                                NULL,
                                INIT_HOME_PAGE,
                                &settingContents,
                                &infoList,
                                NULL,
                                app_quit);
}

#endif
