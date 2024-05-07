#include<thread>


#include<algorithm>




#include<stdlib.h>
#include<unordered_set>
#include<sys/types.h>
#include<functional>
#include<signal.h>







#include<vector>
#include<unistd.h>

#include<chrono>

#include<string>




#include<time.h>

#include<sys/stat.h>

#include<unordered_map>





#include<map>

#include<iomanip>












#include<iostream>

#include<cstring>


#include<array>



#include<mutex>









#include<sys/time.h>
#include<stdexcept>


#define DR_LOG(level) BOOST_LOG_SEV(theOneAndOnlyController->getLogger(), level) 
#define MSG_ID_LEN (128)
#define STATS_COUNTER_CREATE(name, desc) \
{ \
	if (theOneAndOnlyController->getStatsCollector().enabled()) { \
		theOneAndOnlyController->getStatsCollector().counterCreate(name, desc); \
	} \
}
#define STATS_COUNTER_INCREMENT(...) \
{ \
	if (theOneAndOnlyController->getStatsCollector().enabled()) { \
		theOneAndOnlyController->getStatsCollector().counterIncrement(__VA_ARGS__) ;\
	} \
}
#define STATS_COUNTER_INCREMENT_BY(...) \
{ \
	if (theOneAndOnlyController->getStatsCollector().enabled()) { \
		theOneAndOnlyController->getStatsCollector().counterIncrement(__VA_ARGS__); \
	} \
}
#define STATS_COUNTER_INCREMENT_BY_NOCHECK(...) theOneAndOnlyController->getStatsCollector().counterIncrement(__VA_ARGS__);
#define STATS_COUNTER_INCREMENT_NOCHECK(...) theOneAndOnlyController->getStatsCollector().counterIncrement(__VA_ARGS__) ;
#define STATS_GAUGE_CREATE(name, desc) \
{ \
	if (theOneAndOnlyController->getStatsCollector().enabled()) { \
		theOneAndOnlyController->getStatsCollector().gaugeCreate(name, desc); \
	} \
}
#define STATS_GAUGE_DECREMENT(...) \
{ \
	if (theOneAndOnlyController->getStatsCollector().enabled()) { \
		theOneAndOnlyController->getStatsCollector().gaugeDecrement(__VA_ARGS__) ;\
	} \
}
#define STATS_GAUGE_DECREMENT_BY(...) \
{ \
	if (theOneAndOnlyController->getStatsCollector().enabled()) { \
		theOneAndOnlyController->getStatsCollector().gaugeDecrement(__VA_ARGS__); \
	} \
}
#define STATS_GAUGE_DECREMENT_BY_NOCHECK(...) theOneAndOnlyController->getStatsCollector().gaugeDecrement(__VA_ARGS__); 
#define STATS_GAUGE_DECREMENT_NOCHECK(...) theOneAndOnlyController->getStatsCollector().gaugeDecrement(__VA_ARGS__);
#define STATS_GAUGE_INCREMENT(...) \
{ \
	if (theOneAndOnlyController->getStatsCollector().enabled()) { \
		theOneAndOnlyController->getStatsCollector().gaugeIncrement(__VA_ARGS__) ;\
	} \
}
#define STATS_GAUGE_INCREMENT_BY(...) \
{ \
	if (theOneAndOnlyController->getStatsCollector().enabled()) { \
		theOneAndOnlyController->getStatsCollector().gaugeIncrement(__VA_ARGS__); \
	} \
}
#define STATS_GAUGE_INCREMENT_BY_NOCHECK(...) theOneAndOnlyController->getStatsCollector().gaugeIncrement(__VA_ARGS__);
#define STATS_GAUGE_INCREMENT_NOCHECK(...) theOneAndOnlyController->getStatsCollector().gaugeIncrement(__VA_ARGS__) ;
#define STATS_GAUGE_SET(...) \
{ \
	if (theOneAndOnlyController->getStatsCollector().enabled()) { \
		theOneAndOnlyController->getStatsCollector().gaugeSet(__VA_ARGS__); \
	} \
}
#define STATS_GAUGE_SET_NOCHECK(...) theOneAndOnlyController->getStatsCollector().gaugeSet(__VA_ARGS__);
#define STATS_GAUGE_SET_TO_CURRENT_TIME(...) \
{ \
	if (theOneAndOnlyController->getStatsCollector().enabled()) { \
		theOneAndOnlyController->getStatsCollector().gaugeSetToCurrentTime(__VA_ARGS__); \
	} \
}
#define STATS_GAUGE_SET_TO_CURRENT_TIME_NOCHECK(...) theOneAndOnlyController->getStatsCollector().gaugeSetToCurrentTime(__VA_ARGS__);
#define STATS_HISTOGRAM_CREATE(...) \
{ \
	if (theOneAndOnlyController->getStatsCollector().enabled()) { \
		theOneAndOnlyController->getStatsCollector().histogramCreate(__VA_ARGS__); \
	} \
}
#define STATS_HISTOGRAM_OBSERVE(...) \
{ \
	if (theOneAndOnlyController->getStatsCollector().enabled()) { \
		theOneAndOnlyController->getStatsCollector().histogramObserve(__VA_ARGS__) ;\
	} \
}
#define STATS_HISTOGRAM_OBSERVE_NOCHECK(...) theOneAndOnlyController->getStatsCollector().histogramObserve(__VA_ARGS__) ;
#define TIMER_B_MSECS (NTA_SIP_T1 * 64)
#define TIMER_C_MSECS (185000)
#define TIMER_D_MSECS (32500)
#define TIMER_H_MSECS (NTA_SIP_T1 * 64)
#define URI_LEN (256)





#define HDR_STR_LEN (1024)
#define MAX_DESTINATIONS (10)




#define HTTP_BODY_LEN (16384)
#define TXNID_LEN (255)
#define URL_LEN (1024)




#define BODY_LEN (8384)
#define HDR_LEN (4192)
#define START_LEN (512)



