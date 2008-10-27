/*
 * Copyright 2008 Julien Ponge. All rights reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>

#include <Security/Authorization.h>
#include <Security/AuthorizationTags.h>

/*
 * Launches an executable as root on MacOS X.
 * 
 * The executable and arguments must be provided on the command line.
 *
 * This code is heavily inspired from the example at
 * http://developer.apple.com/documentation/Security/Conceptual/authorization_concepts/03authtasks/chapter_3_section_4.html
 *
 */
int main(int argc, const char** argv)
{
    // Check that we have enough arguments
    if (argc < 3)
    {
        return -1;
    }
    
    
    // Grab an authorization reference
    OSStatus status;
    AuthorizationFlags flags = kAuthorizationFlagDefaults;
    AuthorizationRef authRef;
    status = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment, flags, &authRef);
    if (status != errAuthorizationSuccess)
    {
        return status;
    }
    
    // Set up the authorization rights
    AuthorizationItem authItems = { kAuthorizationRightExecute, 0, NULL, 0 };
    AuthorizationRights authRights = { 1, &authItems };
    flags = kAuthorizationFlagDefaults |
            kAuthorizationFlagInteractionAllowed |
            kAuthorizationFlagPreAuthorize |
            kAuthorizationFlagExtendRights;
    status = AuthorizationCopyRights(authRef, &authRights, NULL, flags, NULL);    
    if (status != errAuthorizationSuccess) 
    {
        return status;
    }
    
    // Prepare the executable + arguments, from the command-line arguments
    int i;
    const char* executable = argv[1];
    char** arguments = (char**) malloc(sizeof(char*) * (argc - 1));
    for (i = 0; i < (argc - 2); ++i)
    {
        arguments[i] = (char*) argv[i + 2];
    }
    arguments[argc - 2] = NULL;
    
    // Run!
    flags = kAuthorizationFlagDefaults;
    status = AuthorizationExecuteWithPrivileges(authRef, executable, flags,
                                                arguments, NULL);
    if (status != errAuthorizationSuccess) 
    {
        return status;
    }
    
    // Cleanup
    AuthorizationFree(authRef, kAuthorizationFlagDefaults);
    return 0;
}
