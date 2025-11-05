#include "metrics_servlet.h"
#include <prometheus/text_serializer.h>
namespace base
{
namespace http
{

    MetricsServlet::MetricsServlet() : Servlet("MetricsServlet")
    {
    }

    int32_t MetricsServlet::handle(base::http::HttpRequest::ptr request,
                                   base::http::HttpResponse::ptr response,
                                   base::SocketStream::ptr session)
    {
        auto registry = GetPrometheusRegistry();
        // auto& counter = prometheus::BuildCounter().Name("sylar_test_counter")
        //                     .Help("Number of counter").Register(*registry);
        // counter.Add({{"url", request->getPath()}}).Increment();
        response->setBody(registry->toString());
        return 0;
    }

    PrometheusRegistry::ptr GetPrometheusRegistry()
    {
        static PrometheusRegistry::ptr s_instance = std::make_shared<PrometheusRegistry>();
        return s_instance;
    }

} // namespace http
} // namespace base
