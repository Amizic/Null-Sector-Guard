#pragma once

#if defined(_WIN32) && defined(NSG_SHARED_LIBRARY)
    #if defined(NSG_BUILDING_LIBRARY)
        #define NSG_API __declspec(dllexport)
    #else
        #define NSG_API __declspec(dllimport)
    #endif
#else
    #define NSG_API
#endif
