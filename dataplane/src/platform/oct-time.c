#include "oct-common.h"
#include "oct-time.h"




CVMX_SHARED uint64_t global_time = 0;
CVMX_SHARED uint64_t seconds_since1970 = 0;




void oct_time_update()
{
    struct timeval time;
    global_time++;
    gettimeofday(&time, NULL);
    seconds_since1970 = (uint64_t)time.tv_sec;
}



