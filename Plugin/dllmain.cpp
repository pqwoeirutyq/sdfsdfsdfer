#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <boost/asio.hpp>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <filesystem>
#include <chrono>
#include <curl/curl.h>
#include <memory>
#include <atomic>
#include <samp.h>
#include <MinHookWrapper.hpp>
#include <RakHook/rakhook.hpp>
#include <RakNet/StringCompressor.h>

using namespace boost::asio;
using namespace boost::asio::ip;
namespace fs = std::filesystem;
using namespace std::chrono;

std::atomic<bool> sampInit = false;
steady_clock::time_point initTime;
std::atomic<bool> redirRemoved = false;
std::string htmlFile = "uiresources/index.html";
std::atomic<bool> scriptInject = false;

std::string getMime(const std::string& ext) {
    if (ext == ".html") return "text/html";
    if (ext == ".css") return "text/css";
    if (ext == ".js") return "application/javascript";
    if (ext == ".png") return "image/png";
    if (ext == ".jpg" || ext == ".jpeg") return "image/jpeg";
    if (ext == ".gif") return "image/gif";
    if (ext == ".svg") return "image/svg+xml";
    if (ext == ".ico") return "image/x-icon";
    if (ext == ".ttf") return "font/ttf";
    if (ext == ".otf") return "font/otf";
    if (ext == ".woff") return "font/woff";
    if (ext == ".woff2") return "font/woff2";
    return "application/octet-stream";
}

std::string readFile(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return "";
    std::stringstream buf;
    buf << f.rdbuf();
    f.close();
    return buf.str();
}

std::string getReqFile(const std::string& req) {
    std::istringstream s(req);
    std::string m, p, pr;
    s >> m >> p >> pr;
    if (p == "/") p = "/index.html";
    size_t pos;
    while ((pos = p.find("%20")) != std::string::npos) p.replace(pos, 3, " ");
    return "uiresources" + p;
}

void removeScript(const std::string& file) {
    std::ifstream in(file);
    if (!in.is_open()) return;
    std::stringstream buf;
    buf << in.rdbuf();
    in.close();
    std::string cont = buf.str();
    size_t start = cont.find("<script>/*u*/");
    if (start != std::string::npos) {
        size_t end = cont.find("/*b*/</script>", start);
        if (end != std::string::npos) {
            cont.erase(start, end - start + 14);
            std::ofstream out(file, std::ios::binary | std::ios::trunc);
            if (out.is_open()) {
                out << cont;
                out.close();
            }
        }
    }
}

void addScript(const std::string& file, const std::string& url) {
    std::this_thread::sleep_for(milliseconds(200));
    removeScript(file);
    std::ifstream in(file);
    if (!in.is_open()) return;
    std::stringstream buf;
    buf << in.rdbuf();
    in.close();
    std::string cont = buf.str();
    std::string script = "<script>/*u*/setTimeout(() => { window.location.href = 'http://127.0.0.1:3874'; }, 250);/*b*/</script>";
    size_t body = cont.find("</body>");
    if (body != std::string::npos) cont.insert(body, script);
    else cont += script;
    std::ofstream out(file, std::ios::binary | std::ios::trunc);
    if (out.is_open()) {
        out << cont;
        out.close();
    }
}

struct MemBuf {
    char* data;
    size_t sz;
    MemBuf() : data(nullptr), sz(0) {}
    ~MemBuf() { free(data); }
};

size_t writeMem(void* cont, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    MemBuf* mem = (MemBuf*)userp;
    char* ptr = (char*)realloc(mem->data, mem->sz + realsize + 1);
    if (ptr == nullptr) return 0;
    mem->data = ptr;
    memcpy(&(mem->data[mem->sz]), cont, realsize);
    mem->sz += realsize;
    mem->data[mem->sz] = 0;
    return realsize;
}

std::string loadJS(const std::string& owner, const std::string& repo, const std::string& path, const std::string& token) {
    CURL* curl = curl_easy_init();
    if (!curl) return "";
    MemBuf buf;
    struct curl_slist* headers = nullptr;
    std::string url = "https://api.github.com/repos/" + owner + "/" + repo + "/contents/" + path;
    if (!token.empty()) headers = curl_slist_append(headers, ("Authorization: token " + token).c_str());
    headers = curl_slist_append(headers, "Accept: application/vnd.github.v3.raw");
    headers = curl_slist_append(headers, "User-Agent: SimpleLoader");
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeMem);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    return (buf.data && buf.sz > 0) ? std::string(buf.data, buf.sz) : "";
}

void injectJS(std::string& html, const std::string& js, bool scriptTag) {
    if (scriptTag && !js.empty()) {
        std::string tag = "\n<script>\n// Injected from GitHub\n" + js + "\n</script>\n";
        size_t body = html.find("</body>");
        if (body != std::string::npos) html.insert(body, tag);
        else html += tag;
    }
}

void startServer() {
    try {
        io_context ctx;
        tcp::acceptor acceptor(ctx, tcp::endpoint(tcp::v4(), 3874));
        addScript(htmlFile, "http://127.0.0.1:3874");
        std::string owner = ""; //owner
        std::string repo = ""; //repo
        std::string jsPath = ""; //jsPath
        std::string token = ""; //token
        std::string jsCont;
        while (true) {
            tcp::socket sock(ctx);
            acceptor.accept(sock);
            try {
                char reqBuf[2048];
                boost::system::error_code err;
                size_t readBytes = sock.read_some(buffer(reqBuf), err);
                if (err == boost::asio::error::eof) continue;
                else if (err) throw boost::system::system_error(err);
                if (readBytes == 0) continue;
                std::string req(reqBuf, readBytes);
                std::string filePath = getReqFile(req);
                if (!fs::exists(filePath) || fs::is_directory(filePath)) {
                    std::string resp = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n<html><body><h1>404 Not Found</h1></body></html>";
                    boost::asio::write(sock, buffer(resp));
                    sock.shutdown(tcp::socket::shutdown_both, err);
                    sock.close();
                    continue;
                }
                std::string fileCont = readFile(filePath);
                if (fileCont.empty() && fs::exists(filePath)) {
                    std::string resp = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/html\r\n\r\n<html><body><h1>500 Internal Server Error</h1><p>Could not read file.</p></body></html>";
                    boost::asio::write(sock, buffer(resp));
                    sock.shutdown(tcp::socket::shutdown_both, err);
                    sock.close();
                    continue;
                }
                if (filePath.find("index.html") != std::string::npos) {
                    if (!scriptInject.load()) {
                        jsCont = loadJS(owner, repo, jsPath, token);
                        if (jsCont.empty()) {}
                        else {
                            injectJS(fileCont, jsCont, true);
                            scriptInject.store(true);
                        }
                    }
                }
                std::string ext = "";
                size_t dot = filePath.find_last_of('.');
                if (dot != std::string::npos) ext = filePath.substr(dot);
                std::string mime = getMime(ext);
                std::string resp =
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: " + mime + "\r\n"
                    "Content-Length: " + std::to_string(fileCont.size()) + "\r\n"
                    "Connection: close\r\n"
                    "\r\n" + fileCont;
                boost::asio::write(sock, buffer(resp));
                sock.shutdown(tcp::socket::shutdown_both, err);
                sock.close();
            }
            catch (const std::exception& ex) {
                if (sock.is_open()) {
                    try {
                        std::string resp = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/html\r\n\r\n<html><body><h1>500 Internal Server Error</h1></body></html>";
                        boost::system::error_code ignored;
                        boost::asio::write(sock, buffer(resp), ignored);
                        sock.shutdown(tcp::socket::shutdown_both, ignored);
                        sock.close();
                    }
                    catch (...) {}
                }
            }
            catch (...) {
                if (sock.is_open()) {
                    try {
                        boost::system::error_code ignored;
                        sock.shutdown(tcp::socket::shutdown_both, ignored);
                        sock.close();
                    }
                    catch (...) {}
                }
            }
        }
    }
    catch (const std::exception& e) {
        MessageBoxA(NULL, e.what(), "Server Error", MB_OK | MB_ICONERROR);
    }
}

class Plugin {
public:
    Plugin(HMODULE hmod);
    ~Plugin();
    static void gameLoop();
    static c_hook<void(*)()> loopHook;
private:
    HMODULE mod;
    std::thread serverThread;
};

inline c_hook<void(*)()> Plugin::loopHook = { 0x561B10 };
std::unique_ptr<Plugin> pl;

void Plugin::gameLoop() {
    static bool hookInit = false;
    if (!hookInit) {
        if (rakhook::initialize() && c_chat::get()->ref() != nullptr) {
            hookInit = true;
            StringCompressor::AddReference();
            initTime = steady_clock::now();
            sampInit.store(true);
        }
        else {
            return loopHook.call_original();
        }
    }
    if (sampInit.load() && !redirRemoved.load()) {
        auto now = steady_clock::now();
        auto elapsed = duration_cast<seconds>(now - initTime);
        if (elapsed.count() >= 2) {
            removeScript(htmlFile);
            redirRemoved.store(true);
        }
    }
    return loopHook.call_original();
}

Plugin::Plugin(HMODULE hmod) : mod(hmod) {
    loopHook.add(&Plugin::gameLoop);
    serverThread = std::thread(startServer);
}

Plugin::~Plugin() {
    loopHook.remove();
    rakhook::destroy();
    if (serverThread.joinable()) serverThread.detach();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        pl = std::make_unique<Plugin>(hModule);
        break;
    case DLL_PROCESS_DETACH:
        pl.reset();
        break;
    }
    return TRUE;
}