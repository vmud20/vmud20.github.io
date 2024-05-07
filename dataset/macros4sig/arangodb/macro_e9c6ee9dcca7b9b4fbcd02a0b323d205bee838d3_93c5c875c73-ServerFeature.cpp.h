








#include<chrono>
#include<cstdlib>






#include<queue>

#include<atomic>
#include<mutex>

#include<optional>



#include<limits>
#include<functional>
#include<vector>

#include<unordered_set>
#include<string>

#include<list>





#include<string_view>


#include<utility>
#include<type_traits>
#include<cstdint>

#include<map>







#include<sstream>



#include<condition_variable>




#include<cmath>
#include<array>



#include<memory>
#include<iostream>





#include<initializer_list>









#include<iosfwd>
#include<unordered_map>
#define DECLARE_COUNTER(x, help)                \
  struct x : arangodb::metrics::CounterBuilder<x> { \
    x() { _name = #x; _help = help; } \
    }
#define DECLARE_GAUGE(x, type, help)    \
  struct x : arangodb::metrics::GaugeBuilder<x, type> { \
    x() { _name = #x; _help = help; } \
    }
#define DECLARE_HISTOGRAM(x, scale, help)                   \
  struct x : arangodb::metrics::HistogramBuilder<x, scale> { \
    x() { _name = #x; _help = help; } \
    }
#define DECLARE_LEGACY_COUNTER(x, help)                \
  struct x : arangodb::metrics::CounterBuilder<x> { \
    x() { _name = #x; _help = help; } \
    }
#define DECLARE_LEGACY_GAUGE(x, type, help) DECLARE_GAUGE(x, type, help)
