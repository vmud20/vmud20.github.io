







#include<atomic>




#include<chrono>

#include<limits>













#include<memory>



#include<cstddef>

#include<thread>

#include<type_traits>

#include<cstdint>



#include<map>



#include<sstream>




#include<queue>

#include<string>

#include<mutex>



#include<iosfwd>


#include<cmath>






#include<iostream>

#include<cstdlib>
#include<utility>






#include<vector>

#include<unordered_set>







#include<unordered_map>


#include<string_view>





#include<condition_variable>
#include<optional>





#include<functional>






#define DECLARE_COUNTER(x, help)                    \
  struct x : arangodb::metrics::CounterBuilder<x> { \
    x() {                                           \
      _name = #x;                                   \
      _help = help;                                 \
    }                                               \
  }
#define DECLARE_GAUGE(x, type, help)                    \
  struct x : arangodb::metrics::GaugeBuilder<x, type> { \
    x() {                                               \
      _name = #x;                                       \
      _help = help;                                     \
    }                                                   \
  }
#define DECLARE_HISTOGRAM(x, scale, help)                    \
  struct x : arangodb::metrics::HistogramBuilder<x, scale> { \
    x() {                                                    \
      _name = #x;                                            \
      _help = help;                                          \
    }                                                        \
  }
#define DECLARE_LEGACY_COUNTER(x, help)             \
  struct x : arangodb::metrics::CounterBuilder<x> { \
    x() {                                           \
      _name = #x;                                   \
      _help = help;                                 \
    }                                               \
  }
#define DECLARE_LEGACY_GAUGE(x, type, help) DECLARE_GAUGE(x, type, help)
