#include "base/application/module.h"
#include "base/singleton.h"
#include <iostream>
#include "base/log/log.h"
#include "base/application/application.h"

static base::Logger::ptr g_logger = _LOG_ROOT();

class A
{
public:
    A() { std::cout << "A::A " << this << std::endl; }

    ~A() { std::cout << "A::~A " << this << std::endl; }
};

std::string bigstr(10, 'a');

class MyModule : public base::RockModule
{
public:
    MyModule() : RockModule("hello", "1.0", "")
    {
        // base::Singleton<A>::GetInstance();
    }

    bool onLoad() override
    {
        base::Singleton<A>::GetInstance();
        std::cout << "-----------onLoad------------" << std::endl;
        return true;
    }

    bool onUnload() override
    {
        base::Singleton<A>::GetInstance();
        std::cout << "-----------onUnload------------" << std::endl;
        return true;
    }

    bool onServerReady() override { return true; }

    bool handleRockRequest(base::RockRequest::ptr request, base::RockResponse::ptr response,
                           base::RockStream::ptr stream) override
    {
        // _LOG_INFO(g_logger) << "handleRockRequest " << request->toString();
        // sleep(1);
        response->setResult(0);
        response->setResultStr("ok");
        response->setBody("echo: " + request->getBody());

        usleep(100 * 1000);
        auto addr = stream->getLocalAddressString();
        if (addr.find("8061") != std::string::npos) {
            if (rand() % 100 < 50) {
                usleep(10 * 1000);
            } else if (rand() % 100 < 10) {
                response->setResult(-1000);
            }
        } else {
            // if(rand() % 100 < 25) {
            //     usleep(10 * 1000);
            // } else if(rand() % 100 < 10) {
            //     response->setResult(-1000);
            // }
        }
        return true;
        // return rand() % 100 < 90;
    }

    bool handleRockNotify(base::RockNotify::ptr notify, base::RockStream::ptr stream) override
    {
        _LOG_INFO(g_logger) << "handleRockNotify " << notify->toString();
        return true;
    }
};

extern "C"
{

    base::Module *CreateModule()
    {
        base::Singleton<A>::GetInstance();
        std::cout << "=============CreateModule=================" << std::endl;
        return new MyModule;
    }

    void DestoryModule(base::Module *ptr)
    {
        std::cout << "=============DestoryModule=================" << std::endl;
        delete ptr;
    }
}
