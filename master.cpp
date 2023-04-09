// master.cpp
#define MASTER
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define DO_LOG
//#define TEST 
//#define DEBUG
#define USE_GC
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>
#ifndef _WIN32
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#define CloseSocket(s) close(s)
#define ZeroMem(a) bzero(&a, sizeof(a))
#define Sleep(ms) usleep(ms * 1000)
typedef int SOCKET;
#else
#include <WinSock2.h>
#define CloseSocket(s) closesocket(s)
#define ZeroMem(a) ZeroMemory(&a, sizeof(a))
typedef int socklen_t;
#ifdef _MSC_VER
#pragma comment(lib, "Ws2_32")
#pragma warning(disable : 4309)
#endif
#define MSG_DONTWAIT 0
#endif
#define SEND_FLAGS 0
#define RECV_FLAGS 0

#define MASTER_PORT 27900
#define FORWARDER_PORT 27901
#define BROWSER_PORT 28910
#define TIMEOUT 65

#define MASTER_REGISTER_SERVER 9
#define MASTER_HEARTBEAT1 1
#define MASTER_HEARTBEAT2 8
#define MASTER_UPDATE_SERVER 3
#define BROWSER_SERVER_LIST 0
#define BROWSER_SERVER_INFO 1
#define BROWSER_FORWARD 2
#define BACKEND_FLAGS 0
#define BROWSER_OUTPUT_BUFFER_SIZE 32168
#define MASTER_OUTPUT_BUFFER_SIZE 4096

#define PROXY_ENABLED

#ifndef DO_LOG
#ifdef printf
#undef printf
#endif
#define printf(...) /* */
#endif

#include "lib/enctypex.h"
#include "lib/json.hpp"
#include "iobuf.h"

typedef std::map<std::string, std::string> Dictionary;

SOCKET master_socket;
SOCKET forwarder_socket;
SOCKET browser_socket;

std::mutex clientMutex;

struct ProxyRequest
{
    std::string host;
    std::string script;
    Dictionary params;
};

typedef ProxyRequest* ProxyRequestPtr;

struct ClientInfo;
typedef unsigned long long server_id;
typedef std::shared_ptr<ClientInfo> ClientInfoRef;
std::map<server_id, ClientInfoRef> clients;

ClientInfoRef findServer(int ip, int port, std::string game, bool internal = false);
void getServers(std::vector<ClientInfoRef>& servers, std::string game = "", bool internal = false);
void debugOutput(const char* buff, int len);
void debugOutputCArray(const char* buff, int len);
SOCKET socketForHost(SOCKET sock, const char* host);
SOCKET sendToProxy(ProxyRequest* req, SOCKET sock);

bool remoteList = true;
std::string masterHost = "m.crymp.net";
int masterPort = 80;

struct ClientInfo
{

    // Shared ( Server / Client ):

    int ip;
    int port;
    int sv_port; // service port, not a server port!!
    int cookie;
    time_t last_recv;
    int packets;
    size_t traffic_in;
    size_t traffic_out;
    bool killed;
    bool sent_challenge;

    socklen_t cl;
    sockaddr_in ci;
    std::string game;

    IOBuf outp;
    IOBuf outp_aside;
    char* inp;

    // Client only:

    bool throwaway;
    bool isTcp;
    bool socket_dead;
    bool crypto_sent;
    SOCKET client_sock;
    unsigned char* encxkeyb;
    unsigned char* challenge_str;

    Dictionary params;
    ClientInfo(int a_ip, int a_port, int a_sv_port, sockaddr_in s_in, int s_len, SOCKET sock = 0)
        : ip(a_ip),
        port(a_port),
        last_recv(0),
        cookie(0),
        packets(0),
        sv_port(a_sv_port),
        client_sock(sock),
        socket_dead(false),
        traffic_in(0),
        traffic_out(0),
        killed(false),
        crypto_sent(false),
        sent_challenge(false),
        throwaway(false)
    {
        isTcp = sock != 0;
        ci = s_in;
        cl = s_len;
        inp = isTcp ? new char[4096] : 0;
        encxkeyb = isTcp ? new unsigned char[261] : 0;
        challenge_str = isTcp ? new unsigned char[16] : 0;
        if (isTcp)
        {
            memset(encxkeyb, 0, 261);
            memset(challenge_str, 0, 8);
        }
#ifndef TEST
        if (isTcp)
        {
            std::thread(ClientInfo::recvThread, this).detach();
        }
#endif
    }

    template<class T>
    T safe_get(const nlohmann::json& obj, const std::string& key, const T& def) {
        if (obj.contains(key)) {
            return obj[key].get<T>();
        }
        else {
            return def;
        }
    }

    ClientInfo(const nlohmann::json& json) : throwaway(true),
        traffic_in(0), traffic_out(0), packets(0),
        cookie(0),
        sv_port(0),
        ip(0), port(0), last_recv(0),
        socket_dead(false),
        crypto_sent(false),
        sent_challenge(false),
        client_sock(0),
        killed(false),
        isTcp(false)
    {
        memset(&ci, 0, sizeof(ci));
        cl = sizeof(ci);
        last_recv = time(0);
        inp = isTcp ? new char[4096] : 0;
        encxkeyb = isTcp ? new unsigned char[261] : 0;
        challenge_str = isTcp ? new unsigned char[8] : 0;
        if (isTcp)
        {
            memset(encxkeyb, 0, 261);
            memset(challenge_str, 0, 8);
        }

        int a, b, c, d;
        sscanf(json["ip"].get<std::string>().c_str(), "%d.%d.%d.%d", &a, &b, &c, &d);
        ip = ((a << 24) | (b << 16) | (c << 8) | d);
        port = json["port"].get<int>();

        params["gamename"] = "crysis";
        params["hostname"] = safe_get<std::string>(json, "name", "");
        params["localip"] = safe_get<std::string>(json, "local_ip", "127.0.0.1");
        if (params["localip"] == "localhost") params["localip"] = "127.0.0.1";
        params["localip0"] = params["localip"];
        params["localport"] = std::to_string(safe_get<int>(json, "local_port", 64087));
        params["publicport"] = std::to_string(safe_get<int>(json, "public_port", 64087));
        params["publicip"] = std::to_string(ip);
        params["hostport"] = params["localport"];

        params["natneg"] = "1";
        params["country"] = "DE";

        params["password"] = safe_get<std::string>(json, "pass", "0");
        params["numplayers"] = std::to_string(safe_get<int>(json, "numpl", 0));
        params["maxplayers"] = std::to_string(safe_get<int>(json, "maxpl", 32));
        params["mapname"] = safe_get<std::string>(json, "mapnm", "Mesa");
        params["timeleft"] = std::to_string(safe_get<int>(json, "ntimel", 0));

        if (params["timeleft"] == "0") {
            params["timeleft"] = "-";
            params["timelimit"] = "-";
        }
        else {
            params["timelimit"] = "180";
        }

        params["official"] = std::to_string(safe_get<int>(json, "ranked", 0));
        params["modname"] = "";
        params["modversion"] = "";

        params["gametype"] = safe_get<std::string>(json, "map", "multiplayer/ps/mesa").find("/ps/") == std::string::npos ? "InstantAction" : "PowerStruggle";
        params["gamemode"] = "game";

        params["dx10"] = std::to_string(safe_get<bool>(json, "dx10", false) ? 1 : 0);
        params["friendlyfire"] = std::to_string(safe_get<bool>(json, "friendlyfire", false) ? 1 : 0);
        params["gamepadsonly"] = std::to_string(safe_get<bool>(json, "gamepadsonly", false) ? 1 : 0);
        params["dedicated"] = std::to_string(safe_get<bool>(json, "dedicated", false) ? 1 : 0);
        params["voicecomm"] = std::to_string(safe_get<bool>(json, "voicecomm", false) ? 1 : 0);
        params["anticheat"] = std::to_string(safe_get<bool>(json, "anticheat", false) ? 1 : 0);
        params["gamever"] = std::string("1.1.1.") + std::to_string(safe_get<int>(json, "ver", 6156));

        int i = 0;
        for (auto& player : json["players"])
        {
            std::string idx = std::to_string(i);
            params["player_" + idx] = player["name"].get<std::string>();
            params["kills_" + idx] = std::to_string(player["kills"].get<int>());
            params["deaths_" + idx] = std::to_string(player["deaths"].get<int>());
            params["rank_" + idx] = std::to_string(player["rank"].get<int>());
            if (player.count("team") > 0)
                params["team_" + idx] = std::to_string(player["team"].get<int>());
            else params["team_" + idx] = "0";
            i++;
        }
    }

    ~ClientInfo()
    {
        if (inp)
        {
            delete[] inp;
            inp = 0;
        }
        if (encxkeyb)
        {
            delete[] encxkeyb;
            encxkeyb = 0;
        }
        if (challenge_str)
        {
            delete[] challenge_str;
            challenge_str = 0;
        }
        if (isTcp && !socket_dead)
        {
            CloseSocket(client_sock);
        }
    }

    void requestKill()
    {
        killed = true;
        if (isTcp)
        {
            CloseSocket(client_sock);
            socket_dead = true;
        }
        else
        {
            last_recv = 0;
        }
    }

    bool isDead()
    {
        return killed || (isTcp && socket_dead) || (!isTcp && (time(0) - last_recv) > TIMEOUT);
    }

    std::string get(std::string index)
    {
        Dictionary::iterator it = params.find(index);
        if (it != params.end())
            return it->second;
        return "";
    }

    std::string get(std::string index, int num)
    {
        Dictionary::iterator it = params.find(index);
        std::string retval = "";
        if (it != params.end())
            retval = it->second;
        if (retval == "")
            retval = std::to_string(num);
        return retval;
    }

    bool has(std::string index)
    {
        return params.find(index) != params.end();
    }

    server_id getId()
    {
        return ClientInfo::makeId(ip, port, sv_port);
    }

    static std::string getStringIp(int ip)
    {
        return std::to_string((ip >> 24) & 255) + "." +
            std::to_string((ip >> 16) & 255) + "." +
            std::to_string((ip >> 8) & 255) + "." +
            std::to_string((ip) & 255);
    }

    ProxyRequestPtr proxifyCrymp()
    {
#ifdef PROXY_ENABLED
        Dictionary crymp;
        /*
                gamespy:
                "localip","localport","natneg","gamename","publicip","publicport",
                "hostname","gamever","hostport","mapname","gametype",
                "numplayers","maxplayers",
                "gamemode","timelimit","password","anticheat","official","voicecomm",
                "friendlyfire","dedicated","dx10","gamepadsonly","timeleft"

                crymp:
                name, pass, proxy_ip, port, numpl, maxpl, map, timel, mapdl, ranked,
                desc, mappic, local, ver, players, cookie
        */
        crymp["name"] = get("hostname");
        crymp["pass"] = get("password");
        crymp["proxy_ip"] = getStringIp(ip);
        const char* secret = getenv("PROXY_SECRET");
        if (secret)
            crymp["proxy_secret"] = secret;
        else
            crymp["proxy_secret"] = "proxy-secret";
        crymp["port"] = get("localport");
        crymp["public_port"] = std::to_string(port);
        crymp["numpl"] = get("numplayers");
        crymp["maxpl"] = get("maxplayers");
        std::string sv_map = get("mapname");
        if (sv_map == "")
            sv_map = "Mesa";
        std::string nmap = "";
        for (auto c : sv_map)
        {
            if (c != ' ')
                nmap += tolower(c);
        }
        sv_map = nmap;
        // sv_map[0] = sv_map[0] & 0x3F;
        crymp["map"] = std::string("multiplayer/") + std::string((get("gametype") == "InstantAction") ? "ia/" : "ps/") + sv_map;
        crymp["timel"] = get("timeleft", 0);
        if (crymp["timel"] == "-") crymp["timel"] = "0";
        crymp["ranked"] = get("official");
        crymp["desc"] = "";
        crymp["mappic"] = "";
        crymp["local"] = get("localip");
        crymp["dx10"] = get("dx10", 0);
        crymp["friendlyfire"] = get("friendlyfire", 0);
        crymp["gamepadsonly"] = get("gamepadsonly", 0);
        crymp["dedicated"] = get("dedicated", 0);
        crymp["voicecomm"] = get("voicecomm", 0);
        crymp["anticheat"] = get("anticheat", 0);
        crymp["ver"] = get("gamever") == "1.1.1.5767" ? "5767" : "6156";

        int numpl = atoi(get("numplayers").c_str());
        std::string players = "";
        for (int i = 0; i < numpl; i++)
        {
            players +=
                std::string("@") + get("player_" + std::to_string(i)) + "%" + get("rank_" + std::to_string(i), 0) + "%" + get("kills_" + std::to_string(i), 0) + "%" + get("deaths_" + std::to_string(i), 0) + "%0" + "%" + get("team_" + std::to_string(i), 0);
        }
        crymp["players"] = players;
        crymp["proxied"] = "1";

        ProxyRequest* pr = new ProxyRequest;
        if (pr)
        {
            pr->host = masterHost;
            pr->script = "/api/up.php";
            pr->params = crymp;
        }
        return pr;
#else
        return 0;
#endif
    }

    void processPacket(const char* buff, int packet_len)
    {
        packets++;
        last_recv = time(0);
        traffic_in += packet_len;
        if (packet_len < 5)
            return;
        outp.reset();
        outp.i8(0xFE).i8(0xFD);

        IOBuf rd; rd.bytes(buff, (size_t)packet_len);
        rd.seek(0);
        char type = rd.i8();
        int packet_id = rd.i32();
        printf("[master] [info] packet type: %d, packet id: %08X, length: %d\n", type, packet_id, packet_len);
        if (type == MASTER_REGISTER_SERVER && sv_port == MASTER_PORT)
        {
            game = rd.sz();
            outp.i8(0x09);
            for (int i = 0; i < 8; i++)
                outp.i8(0);
            this->sendUDPResponse(outp.size());
            printf("[master] [msg] subscribed %s:%d to game: %s\n", inet_ntoa(ci.sin_addr), ntohs(ci.sin_port), game.c_str());
        }
        else if (type == MASTER_UPDATE_SERVER && sv_port == MASTER_PORT)
        {
            int n = 0;
            std::string key = "";
            std::string val = "";
            this->cookie = packet_id;
            int p_off = 0;
            for (int i = 0; i < rd.capacity(); i++)
            {
                char c = rd[i];
                if (i > 0 && c == 0 && rd[i - 1] == 0)
                {
                    p_off = i + 3;
                    break;
                }
                if (c == 0)
                {
                    if (n % 2 == 1)
                    {
                        params[key] = val;
                        val = "";
                        key = "";
                    }
                    n++;
                }
                else
                    ((n % 2 == 0) ? key : val) += c;
            }
            std::vector<std::string> indexes;
            int d_off = 0;
            if ((p_off + 5) < packet_len && rd[p_off] == 'p' && rd[p_off - 1] > 0)
            {
                for (int i = p_off; i < rd.capacity(); i++)
                {
                    char c = rd[i];
                    if (!c)
                    {
                        if (key.length() == 0)
                        {
                            d_off = i + 1;
                            break;
                        }

                        indexes.push_back(key);
                        key = "";
                    }
                    else
                    {
                        key += c;
                    }
                }
            }
            if (d_off && (d_off + 5) < packet_len && indexes.size())
            {
                size_t ctr = 0;
                for (int i = d_off; i < rd.capacity(); i++)
                {
                    char c = rd[i];
                    if (!c)
                    {
                        if (val.length() == 0)
                            break;
                        size_t idx = ctr / indexes.size();
                        std::string item = indexes[ctr % indexes.size()];
                        item += std::to_string(idx);
                        params[item] = val;
                        // printf("item found: %s -> %s\n", item.c_str(), val.c_str());
                        val = "";
                        ctr++;
                    }
                    else
                    {
                        val += c;
                    }
                }
            }
            bool existed = false;
            if (!remoteList)
            {
                ClientInfoRef existent = findServer(ip, atoi(get("localport").c_str()), game);
                if (existent && existent.get() != this)
                {
                    existent->requestKill();
                    existed = true;
                }
            }
            params["country"] = "KP";
            params["publicip"] = std::to_string(ip);
            params["publicport"] = get("localport");
            params["localip"] = get("localip0");
            outp.i8(0x01);
            outp.i32(packet_id);
            for (int i = 0; i < 21; i++)
            {
                outp.i8((rand() % 20) + 65);
            }
            outp.i8(0);
            if (!sent_challenge)
                this->sendUDPResponse(outp.size());
            sent_challenge = true;
            printf("[master] [msg] updated server %s:%d, killed old: %d\n", inet_ntoa(ci.sin_addr), ntohs(ci.sin_port), existed ? 1 : 0);
            // this->proxifyCrymp();
        }
        else if (type == MASTER_HEARTBEAT1 || type == MASTER_HEARTBEAT2)
        {
            outp.i8(MASTER_HEARTBEAT1 == type ? 0x0A : MASTER_HEARTBEAT2);
            outp.i32(packet_id);
            this->sendUDPResponse(outp.size());
        }
    }
    void processFwdPacket(char* buff, int packet_len)
    {
        if (packet_len < 5)
            return;
        int type = buff[7];
        if (type == 0)
        {
            int cl_id = *(int*)(buff + 8);
            int local_ip = *(int*)(buff + 15);
            short local_port = *(short*)(buff + 19);
            outp.reset().bytes(buff, 21);
            this->sendUDPResponse(outp.size());
        }
    }

    void processStream(const char* buff, size_t stream_len)
    {
        packets++;
        last_recv = time(0);
        traffic_in += stream_len;
        IOBuf rd; rd.bytes(buff, stream_len);
        rd.seek(0);
        char req_type = rd.i8();
        if (req_type == BROWSER_SERVER_LIST)
        {
            rd.seek(7);
            this->game = rd.sz();
            rd.sz();
            for (int i = 0; i < 8; i++)
                challenge_str[i + 8] = challenge_str[i] = rd.i8();
            rd.i16();
            std::vector<std::string> params;
            std::string param = "";
            for (int i = 0; i < rd.capacity(); i++)
            {
                char c = rd[i];
                if (c == '\\' || !c)
                {
                    if (param.length() > 0)
                        params.push_back(param);
                    param = "";
                    if (!c)
                        break;
                }
                else
                    param += c;
            }

            outp.reset();
            
            char gamekey[32] = "ZvZDcL";
            int headerLen = 0;
            prepareCryptoHeader(outp, gamekey, headerLen);

            // write header with requesters IP, port and num params
            outp.I32(ip).I16(port).i16((int)params.size());

            // write params as param1 \0 \0 param2 \0 \0...
            for (size_t i = 0; i < params.size(); i++)
            {
                outp.sz(params[i]).i8(0);
            }
            
            // if we still have enough space in buffer continue
            std::vector<ClientInfoRef> servers;
            if (params.size() > 0) {
                getServers(servers, game);
            }

            for (size_t i = 0; i < servers.size(); i++)
            {
                ClientInfoRef server = servers[i];
                if (server->isDead())
                {
                    continue;
                }

                // server header: 9 bytes
                char type = 0x74;
                outp.i8(type).I32(server->ip).I16(atoi(server->get("localport").c_str())).I16(server->port);

                printf("[browser] [info] adding server %s to list\n", server->get("hostname").c_str());

                // write server params as \xFF value1 \0 \FF value2 \0 ...
                for (size_t j = 0; j < params.size(); j++)
                {
                    if (!server->has(params[j]))
                    {
                        printf("[browser] [err] server %s doesn't have %s key\n", server->get("hostname").c_str(), params[j].c_str());
                        continue;
                    }
                    outp.i8(0xFF).sz(server->get(params[j]));
                }
            }

            // server list ends as \0 \xFF \xFF \xFF \x FF
            outp.i8(0).I32(-1);
#ifdef DEBUG
            debugOutput(outp.raw(), outp.size());
#endif
            if (params.size() > 0) {
                // only do this if server list was actually requested
                outp.seek(headerLen);
                enctypex_func6e((unsigned char*)encxkeyb, outp);
                printf("[browser] [info] sending server list to %016llX, challenge: %016llX\n", getId(), *(unsigned long long*)challenge_str);
                sendTCPResponse(outp.size());
            } else if (headerLen > 0) {
                printf("[browser] [info] sending just header to %016llX\n", getId());
                // otherwise jsut send header if requested
                sendTCPResponse(headerLen);
                //crypto_sent = false;
            }
        }
        else if (req_type == BROWSER_SERVER_INFO)
        {
            int sv_ip = rd.I32();
            int sv_port = rd.I16();

            printf("[browser] [info] %016llX requesting info about %08X:%04X, game: %s\n", getId(), sv_ip, sv_port, this->game.c_str());
            ClientInfoRef server = findServer(sv_ip, sv_port, this->game);
            if (server)
            {
                int headerLen = 0;
                char gamekey[32] = "ZvZDcL";
                outp.reset();
                prepareCryptoHeader(outp, gamekey, headerLen);
                // reserve header
                for(int i=0; i<20; i++) outp.i8(0);
                int flags = 0;
                printf("[browser] [info] server found: %s\n", server->get("hostname").c_str());
                fflush(stdout);
                std::vector<std::string> req_params = {
                    "localip", "localport", "natneg", "gamename", "publicip", "publicport",
                    "hostname", "gamever", "hostport", "mapname", "gametype",
                    "numplayers", "maxplayers",
                    "gamemode", "timelimit", "password", "anticheat", "official", "voicecomm",
                    "friendlyfire", "dedicated", "dx10", "gamepadsonly", "timeleft" };
                int numpl = atoi(server->get("numplayers").c_str());
                // also push player valeus
                for (int i = 0; i < numpl; i++)
                {
                    req_params.push_back("player_" + std::to_string(i));
                    req_params.push_back("team_" + std::to_string(i));
                    req_params.push_back("kills_" + std::to_string(i));
                    req_params.push_back("deaths_" + std::to_string(i));
                    req_params.push_back("rank_" + std::to_string(i));
                }
                // write key value pairs as key \0 value \0 ...
                for (size_t i = 0; i < req_params.size(); i++)
                {
                    std::string key = req_params[i];
                    if (!server->has(key))
                        continue;
                    std::string val = server->get(key);
                    if (val.length() == 0)
                        val = "0";
#ifdef DEBUG
                    printf("[browser] [info] adding %s,%s \n", key.c_str(), val.c_str());
                    fflush(stdout);
#endif
                    size_t kl = key.length();
                    size_t vl = val.length();
                    if (kl == 0)
                        continue;
                    size_t pl = kl + vl + 2;
                    outp.sz(key).sz(val);
                }
                // check for final overflow here
                outp.i8(0);
                int len = (int)outp.size();
                // write header as u16[content length] + 0x2BE + server ip + server port + server local ip + server port + server ip
                outp.seek(headerLen);
                
                int i0, i1, i2, i3;
                sscanf(server->get("localip0").c_str(), "%d.%d.%d.%d", &i0, &i1, &i2, &i3);
                
                outp.I16(len).I16(0x02BE).I32(server->ip).I16(atoi(server->get("hostport").c_str()));
                outp.i8(i0).i8(i1).i8(i2).i8(i3).I16(atoi(server->get("hostport").c_str()));
                outp.I32(server->ip);

                printf("[browser] [info] sending server info to %016llX, length: %zd bytes, challenge: %016llX\n", getId(), len, *(unsigned long long*)challenge_str);
#ifdef DEBUG
                debugOutput(outp.raw(), outp.size());
#endif
                outp.seek(headerLen);
                enctypex_func6e((unsigned char*)encxkeyb, outp);
                sendTCPResponse(outp.size());
            }
        }
        else if (req_type == BROWSER_FORWARD)
        {
            int sv_ip = ((buff[3] & 0xFF) << 24) | ((buff[4] & 0xFF) << 16) | ((buff[5] & 0xFF) << 8) | ((buff[6] & 0xFF));
            int sv_port = ((buff[7] & 0xFF) << 8) | ((buff[8] & 0xFF));
            printf("[browser] [info] %016llX requesting forwarding to %08X:%04X, game: %s\n", getId(), sv_ip, sv_port, this->game.c_str());
            ClientInfoRef server = findServer(sv_ip, sv_port, this->game);
            if (server && !server->throwaway)
            {
                rd.seek(9);
                server->forwardBytes(this, rd.cur(), rd.capacity());
            }
        }
    }

    int sendUDPResponse(int len, bool sideBuffer = false)
    {
        traffic_out += len;
#ifdef DEBUG
        debugOutputCArray(sideBuffer ? outp_aside.raw() : outp.raw(), len);
#endif
        return sendto(sv_port == MASTER_PORT ? master_socket : forwarder_socket, sideBuffer ? outp_aside.raw() : outp.raw(), len, 0, (sockaddr*)&ci, cl);
    }

    int sendTCPResponse(size_t len)
    {
        traffic_out += len;
#ifdef DEBUG
        debugOutputCArray(outp.raw(), len);

        printf("client sock: %d, outp: %p, len: %d", client_sock, outp, len);
#endif

#ifdef TEST
        return 0;
#else
        return send(client_sock, outp.raw(), (int)len, SEND_FLAGS);
#endif
    }

    void forwardBytes(ClientInfo* from, const char* buff, int len)
    {
        if (len > 240)
            len = 240;
        outp_aside.reset().i16(0xFEFD).i8(0x06);
        outp_aside.i32(cookie);
        for (int i = 0; i < 4; i++)
            outp_aside.i8(rand() & 0xFF);
        outp_aside.bytes(buff, len);
        sendUDPResponse(outp_aside.size(), true);
    }

    static inline server_id makeId(int cl_ip, int cl_port, int svc_port)
    {
        return (((server_id)svc_port) << 48) | ((((server_id)cl_ip) & 0xFFFFFFFF) << 16) | cl_port;
    }

    static void recvThread(ClientInfo* client)
    {
        if (!client)
            return;
        printf("[browser] [info] receive thread is active for %016llX\n", client->getId());
        while (true && client)
        {
            short hdrlen;
            int hdr = recv(client->client_sock, (char*)&hdrlen, 2, 0);
            if (hdr == 0) {
                client->socket_dead = true;
                CloseSocket(client->client_sock);
                printf("[browser] [info] %016llX received %d bytes, closing (err: %s)\n", client->getId(), hdr, strerror(errno));
                return;
            }
            else if (hdr > 0) {
                hdrlen = ntohs(hdrlen) - 2;
                int len = recv(client->client_sock, client->inp, hdrlen, 0);
                if (len == 0)
                {
                    client->socket_dead = true;
                    CloseSocket(client->client_sock);
                    printf("[browser] [info] %016llX received %d bytes, closing (err: %s)\n", client->getId(), len, strerror(errno));
                    return;
                }
                else if (len > 0)
                {
                    try {
                        client->processStream(client->inp, len);
                    } catch(std::runtime_error& err) {
                        printf("[browser] [err] error during stream processing: %s\n", err.what());
                        client->requestKill();
                    }
                }
            }
        }
    }

    char* readString(char*& buff, size_t* len)
    {
        char* str = buff;
        if (*len <= 0)
            return str;
        size_t i = 0;
        while (i < *len)
        {
            if (buff[i] == 0)
            {
                *len -= i + 1;
                buff += i + 1;
                return str;
            }
            i++;
        }
        *len = 0;
        buff += i + 1;
        return str;
    }

    IOBuf& prepareCryptoHeader(IOBuf& outp, char* gamekey, int& headerLen)
    {
        if (crypto_sent)
        {
            headerLen = 0;
            return outp;
        }
        memcpy(challenge_str, challenge_str + 8, 8);
        headerLen = 37;

        for(int i=0; i<37; i++) {
            switch(i) {
                case 0:
                    outp.i8(230);
                    break;
                case 1:
                case 2:
                    outp.i8(0);
                    break;
                case 11:
                    outp.i8(243);
                    break;
                default:
                    outp.i8('A');
                    break;
            }
        }

        outp.seek(12);
        enctypex_funcx((unsigned char*)encxkeyb, (unsigned char*)gamekey, (unsigned char*)challenge_str, outp);
        outp.end();
        crypto_sent = true;
        return outp;
    }
};

void getServers(std::vector<ClientInfoRef>& servers, std::string game, bool internal)
{
    if (remoteList && !internal)
    {
        SOCKET sock = socketForHost(0, masterHost.c_str());
        std::string cmd = std::string("GET /api/servers HTTP/1.1\r\nHost: ") + masterHost + "\r\nConnection: close\r\n\r\n";
        int res = send(sock, cmd.c_str(), (int)cmd.length(), SEND_FLAGS);
        std::string data;
        char buf[4000];
        if (res <= 0)
        {
            printf("[browser] [err] failed to send HTTP request to master\n");
            return;
        }
        for (;;)
        {
            memset(buf, 0, sizeof(buf));
            int len = recv(sock, buf, sizeof(buf) - 1, RECV_FLAGS);
            if (len <= 0)
            {
                CloseSocket(sock);
                break;
            }
            else
            {
                data.append(buf, buf + len);
            }
        }
        auto pivot = data.find("\r\n\r\n");
        if (pivot == std::string::npos)
        {
            printf("[browser] [err] couldn't find rnrn in master response\n");
            return;
        }
        std::string servers_data = data.substr(pivot + 4);
        if (servers_data.length() < 2)
        {
            printf("[browser] [err] didnt receve any servers\n");
            return;
        }
        try
        {
            auto parsed = nlohmann::json::parse(servers_data);
            for (auto& server : parsed)
            {
                auto sv = std::make_shared<ClientInfo>(server);
                if(sv->get("hostname").length() > 0)
                    servers.push_back(sv);
            }
        }
        catch (std::exception& ex)
        {
            printf("[browser] [err] failed to parse response JSON: %s\n", ex.what());
            printf("[browser] [err] JSON response: %s\n", servers_data.c_str());
            servers.clear();
            return;
        }
    }
    else
    {
        servers.clear();
        clientMutex.lock();
        for (std::map<server_id, ClientInfoRef>::iterator it = clients.begin(); it != clients.end(); it++)
        {
            if (it->second && !it->second->isDead() && it->second->sv_port == MASTER_PORT && !it->second->isTcp && (game.length() == 0 || it->second->get("gamename") == game) && it->second->params.size() > 0)
                servers.push_back(it->second);
        }
        clientMutex.unlock();
    }
}

ClientInfoRef findServer(int ip, int port, std::string game, bool internal)
{
    if (remoteList && !internal)
    {
        SOCKET sock = socketForHost(0, masterHost.c_str());
        std::string cmd = std::string("GET /api/server?ip=") + ClientInfo::getStringIp(ip) + "&port=" + std::to_string(port) + " HTTP/1.1\r\nHost: " + masterHost + "\r\nConnection: close\r\n\r\n";
        int res = send(sock, cmd.c_str(), (int)cmd.length(), SEND_FLAGS);
        std::string data;
        char buf[4000];
        if (res <= 0)
        {
            printf("[browser] [err/2] failed to send HTTP request to master\n");
            return 0;
        }
        for (;;)
        {
            memset(buf, 0, sizeof(buf));
            int len = recv(sock, buf, sizeof(buf) - 1, RECV_FLAGS);
            if (len <= 0)
            {
                CloseSocket(sock);
                break;
            }
            else
            {
                data.append(buf, buf + len);
            }
        }
        auto pivot = data.find("\r\n\r\n");
        if (pivot == std::string::npos)
        {
            printf("[browser] [err/2] couldn't find rnrn in master response\n");
            return 0;
        }
        std::string servers_data = data.substr(pivot + 4);
        if (servers_data.length() < 2)
        {
            printf("[browser] [err/2] didnt receve any servers\n");
            return 0;
        }
        try
        {
            auto parsed = nlohmann::json::parse(servers_data);
            if (parsed.count("ip") == 0) {
                return nullptr;
            }
            return std::make_shared<ClientInfo>(parsed);
        }
        catch (std::exception& ex)
        {
            printf("[browser] [err/2] failed to parse response JSON: %s\n", ex.what());
            return 0;
        }
    }
    else
    {
        clientMutex.lock();
        for (std::map<server_id, ClientInfoRef>::iterator it = clients.begin(); it != clients.end(); it++)
        {
            if (it->second && !it->second->isDead() && it->second->sv_port == MASTER_PORT && !it->second->isTcp && it->second->get("gamename") == game && it->second->ip == ip && atoi(it->second->get("localport").c_str()) == port)
            {
                ClientInfoRef ci = it->second;
                clientMutex.unlock();
                return ci;
            }
        }
        clientMutex.unlock();
        return 0;
    }
}

void debugOutput(const char* p, int len)
{
    for (int i = 0; i < len; i++)
    {

        if (!isprint((unsigned int)p[i] & 255))
            printf(" %02X ", (unsigned int)(p[i]) & 0xFF);
        else
            printf("%c", p[i]);
    }
    printf("\n\n-----------\n\n");
    fflush(stdout);
}

void debugOutputCArray(const char* p, int len)
{
    printf("unsigned char buff[%d]={ ", len);
    for (int i = 0; i < len; i++)
    {
        printf("0x%02X, ", p[i] & 0xFF);
    }
    printf("};\n");
}

int deployGarbageCollector()
{
    printf("[gc] garbage collector active\n");
    fflush(stdout);
    while (true)
    {
        clientMutex.lock();
        for (std::map<server_id, ClientInfoRef>::iterator it = clients.begin(); it != clients.end();)
        {
            ClientInfoRef client = it->second;
            if (client && client->isDead())
            {
                printf("[gc] [info] removing %016llX for inactivity\n", client->getId());
                it = clients.erase(it);
            }
            else
                it++;
        }
        clientMutex.unlock();
        Sleep(5000);
    }
}

int deployMaster()
{
    printf("[master] [info] initiating master\n");
    fflush(stdout);
    master_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockaddr_in si;
    ZeroMem(si);
    si.sin_family = AF_INET;
    si.sin_port = htons(MASTER_PORT);
    if (bind(master_socket, (sockaddr*)&si, sizeof(si)) < 0)
    {
        printf("[master] [error] failed to bind to address: %s\n", strerror(errno));
        return 1;
    }
    printf("[master] [info] master online\n");
    fflush(stdout);
    char buffer[2048]; // safe: 2048 > MTU ( 1500 )
    while (true)
    {
        ClientInfoRef client;
        sockaddr_in ci;
        socklen_t cl = sizeof(ci);
        int len = recvfrom(master_socket, buffer, 2048, 0, (sockaddr*)&ci, &cl);
        if (len < 0)
        {
            printf("[master] [error] failed to receive: %s\n", strerror(errno));
        }
        int ip = ntohl(ci.sin_addr.s_addr);
        int port = ntohs(ci.sin_port);
        server_id id = ClientInfo::makeId(ip, port, MASTER_PORT);
        {
            std::lock_guard<std::mutex> lock(clientMutex);
            std::map<server_id, ClientInfoRef>::iterator it = clients.find(id);
            if (it != clients.end())
            {
                client = it->second;
                if (!client)
                {
                    clients.erase(it);
                    continue;
                }
                printf("[master] [info] reusing existing client (%016llX)\n", id);
            }
            else
            {
                client = std::make_shared<ClientInfo>(ip, port, MASTER_PORT, ci, cl);
                if (client)
                {
                    clients[id] = client;
                }
                else
                {
                    printf("[master] [error] failed to allocate new client!!!\n");
                    continue;
                }
                printf("[master] [info] allocated new client (%016llX)\n", id);
            }
            printf("[master] [info] received from %08X:%04X (%016llX) %d bytes\n", ip, port, id, len);
        }
        try {
            client->processPacket(buffer, len);
        } catch(std::runtime_error& err) {
            printf("[master] [error] error during packet processing: %s\n", err.what());
        }
    }
    return 0;
}

int deployForwarder()
{
    printf("[forwarder] [info] initiating master\n");
    fflush(stdout);
    forwarder_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockaddr_in si;
    ZeroMem(si);
    si.sin_family = AF_INET;
    si.sin_port = htons(FORWARDER_PORT);
    if (bind(forwarder_socket, (sockaddr*)&si, sizeof(si)) < 0)
    {
        printf("[forwarder] [error] failed to bind to address: %s\n", strerror(errno));
        return 1;
    }
    printf("[forwarder] [info] master online\n");
    fflush(stdout);
    char buffer[2048]; // safe: 2048 > MTU ( 1500 )
    while (true)
    {
        ClientInfoRef client;
        sockaddr_in ci;
        socklen_t cl = sizeof(ci);
        int len = recvfrom(forwarder_socket, buffer, 2048, 0, (sockaddr*)&ci, &cl);
        if (len < 0)
        {
            printf("[forwarder] [error] failed to receive: %s\n", strerror(errno));
        }
        int ip = ntohl(ci.sin_addr.s_addr);
        int port = ntohs(ci.sin_port);
        server_id id = ClientInfo::makeId(ip, port, FORWARDER_PORT);
        {
            std::lock_guard<std::mutex> lock(clientMutex);
            std::map<server_id, ClientInfoRef>::iterator it = clients.find(id);
            if (it != clients.end())
            {
                client = it->second;
                if (!client)
                {
                    clients.erase(it);
                    continue;
                }
                printf("[master] [info] reusing existing client (%016llX)\n", id);
            }
            else
            {
                client = std::make_shared<ClientInfo>(ip, port, FORWARDER_PORT, ci, cl);
                if (client)
                {
                    clients[id] = client;
                }
                else
                {
                    printf("[master] [error] failed to allocate new client!!!\n");
                    continue;
                }
                printf("[master] [info] allocated new client (%016llX)\n", id);
            }
            printf("[master] [info] received from %08X:%04X (%016llX) %d bytes\n", ip, port, id, len);
        }
        client->processFwdPacket(buffer, len);
    }
    return 0;
}

int deployServerBrowser()
{
    printf("[browser] [info] initiating server browser\n");
    fflush(stdout);
    browser_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

#ifndef _WIN32
    int optval = 1;
    setsockopt(browser_socket, SOL_SOCKET, SO_REUSEADDR, (const void*)&optval, sizeof(int));
#endif

    sockaddr_in si;
    ZeroMem(si);
    si.sin_family = AF_INET;
    si.sin_port = htons(BROWSER_PORT);
    if (bind(browser_socket, (sockaddr*)&si, sizeof(si)) < 0)
    {
        printf("[browser] [error] failed to bind to address: %s\n", strerror(errno));
        return 1;
    }
    listen(browser_socket, 800);
    while (true)
    {
        sockaddr_in ci;
        socklen_t cl = sizeof(ci);
        SOCKET client_sock = accept(browser_socket, (sockaddr*)&ci, &cl);
        if (client_sock < 0)
        {
            printf("[browser] [error] failed to accept: %s\n", strerror(errno));
            continue;
        }

        struct timeval tv;
        tv.tv_sec = TIMEOUT;
        tv.tv_usec = 0;
        setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

        int ip = ntohl(ci.sin_addr.s_addr);
        int port = ntohs(ci.sin_port);
        server_id id = ClientInfo::makeId(ip, port, BROWSER_PORT);
        clientMutex.lock();
        std::map<server_id, ClientInfoRef>::iterator it = clients.find(id);
        ClientInfoRef client = 0;
        if (it != clients.end())
        {
            printf("[browser] [info] reusing existing client (%016llX)\n", id);
            client = it->second;
        }
        else
        {
            client = std::make_shared<ClientInfo>(ip, port, BROWSER_PORT, ci, cl, client_sock);
            if (client)
            {
                clients[id] = client;
                printf("[browser] [info] allocated new client (%016llX)\n", id);
            }
            else
            {
                printf("[browser] [error] failed to allocate new client!!!\n");
            }
        }
        clientMutex.unlock();
    }
    return 0;
}

std::string urlEncode(std::string str)
{
    std::string n = "";
    static char hex[17] = "0123456789ABCDEF";
    for (auto c : str)
    {
        if (!isalnum(c))
        {
            n += "%";
            n += hex[(c >> 4) & 0xF];
            n += hex[c & 0xF];
        }
        else
            n += c;
    }
    return n;
}

SOCKET socketForHost(SOCKET sock, const char* host)
{
    SOCKET s = 0;

    if (sock)
    {
        s = sock;
    }
    else
    {
        s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s < 0) {
            printf("[sock] [err] failed to create new socket\n");
            return 0;
        }
    }

    if (!sock)
    {
        hostent* h = gethostbyname(host);
        if (h)
        {
            sockaddr_in ci;
            in_addr* ip = (in_addr*)h->h_addr;
            if (!ip)
            {
                printf("[sock] [err] failed to resolve host, null ip\n");
                return 0;
            }
            ZeroMem(ci);
            ci.sin_addr = *ip;
            ci.sin_port = htons(masterPort);
            ci.sin_family = AF_INET;
            if (connect(s, (const sockaddr*)&ci, sizeof(ci)) == 0)
            {
                return s;
            }
            else
            {
                printf("[sock] [err] failed to connect\n");
                return 0;
            }
        }
        else
        {
            printf("[sock] [err] failed to resolve host name\n");
            return 0;
        }
    }
    else
    {
        return sock;
    }
}

SOCKET sendToProxy(ProxyRequest* req, SOCKET sock)
{
    printf("[proxy] [info] proxying request for %s (%s:%s)\n", req->params["name"].c_str(), req->params["proxy_ip"].c_str(), req->params["port"].c_str());
    std::string data = "POST " + req->script + " HTTP/1.1\r\nHost: " + req->host + "\r\nContent-type: application/x-www-form-urlencoded\r\nConnection: keep-alive\r\nContent-length: ";
    std::string query = "";
    bool first = true;
    for (auto& it : req->params)
    {
        if (!first)
            query += "&";
        query += it.first + "=" + urlEncode(it.second);
        first = false;
    }
    data += std::to_string(query.length()) + "\r\n\r\n" + query;
    sock = socketForHost(sock, req->host.c_str());

    send(sock, data.c_str(), (int)data.length(), 0);
    static char bf[800];
    memset(bf, 0, sizeof(bf));
    recv(sock, bf, sizeof(bf), 0);
    if (!strstr(bf, "200 OK"))
    {
        printf("[proxy] [err] sending server %s:%s to proxy failed\n", req->params["proxy_ip"].c_str(), req->params["port"].c_str());
        printf("request: %s\n", query.c_str());
        printf("response: %s\n", bf);
    }
    // printf("[proxy] [info] received %s from proxy\n", bf);
    return sock;
}

void deployProxyDispatcher()
{
    while (true)
    {
        std::vector<ClientInfoRef> servers;
        getServers(servers, "crysis", true);
        SOCKET sock = 0;
        for (auto& it : servers)
        {
            ProxyRequestPtr req = it->proxifyCrymp();
            if (req)
            {
                req->host = masterHost;
                sock = sendToProxy(req, sock);
                delete req;
            }
        }
        if (sock)
        {
            CloseSocket(sock);
            sock = 0;
        }
        Sleep(45000);
    }
}

int main(int argc, const char** argv)
{
    for (int i = 0; i < argc - 1; i++)
    {
        if (strcmp(argv[i], "-p") == 0)
        {
            masterPort = atoi(argv[i + 1]);
        }
        if (strcmp(argv[i], "-h") == 0)
        {
            masterHost = argv[i + 1];
        }
        if (strcmp(argv[i], "-r") == 0)
        {
            remoteList = strcmp(argv[i + 1], "0") != 0;
        }
    }
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(0x202, &wsaData);
#endif
#ifdef PROXY_ENABLED
    std::thread proxyThread(deployProxyDispatcher);
    proxyThread.detach();
#endif
#ifdef TEST
    sockaddr_in si;
    ZeroMem(si);
    for (int i = 0; i < 2; i++)
    {
        ClientInfoRef server = std::make_shared<ClientInfo>(INADDR_LOOPBACK, 21330 + i, MASTER_PORT, si, 0, 0);
        server->params["localip0"] = "192.168.1.105";
        server->params["localport"] = std::to_string(64087 + i);
        server->params["hostport"] = std::to_string(64087 + i);
        server->params["natneg"] = "1";
        server->params["statechanged"] = "3";
        server->params["gamename"] = "crysis";
        server->params["publicip"] = "0";
        server->params["publicport"] = "0";
        server->params["hostname"] = "Test Serverik" + std::string(" ") + std::to_string(i);
        server->params["gamever"] = "1.1.1.6156";
        server->params["hostport"] = std::to_string(21330 + i);
        server->params["gametype"] = "PowerStruggle";
        server->params["numplayers"] = "0";
        server->params["maxplayers"] = "32";
        server->params["gamemode"] = "pre-game";
        server->params["timelimit"] = "180";
        server->params["password"] = "0";
        server->params["anticheat"] = "0";
        server->params["official"] = "0";
        server->params["voicecomm"] = "0";
        server->params["friendlyfire"] = "0";
        server->params["dedicated"] = "1";
        server->params["dx10"] = "0";
        server->params["gamepadsonly"] = "0";
        server->params["timeleft"] = "-";
        server->params["country"] = "KP";
        clients[server->getId()] = server;

        char req0[] = "\x03\xcd\x98\x07\x3a"
            "test\x00var\x00\x00\x00\x05player_\x00kills_\x00\x64\x65\x61ths_\x00rank_\x00\x00"
            "Zi;\x00\x31\x00\x31\x00\x31\x00\x43omrade\x00\x32\x00\x33\x00\x34\x00\x00\x00";

        server->processPacket(req0, 74);
    }

    ClientInfoRef client = std::make_shared<ClientInfo>(INADDR_LOOPBACK, 5004, BROWSER_PORT, si, 0, 1);
    unsigned char req1[] = {
        0x00, 0xd0, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00,
        0x00, 0x63, 0x72, 0x79, 0x73, 0x69, 0x73, 0x00,
        0x63, 0x72, 0x79, 0x73, 0x69, 0x73, 0x00, 0x75,
        0x7b, 0x2b, 0x69, 0x48, 0x3d, 0x66, 0x2d, 0x00,
        0x5c, 0x68, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d,
        0x65, 0x5c, 0x67, 0x61, 0x6d, 0x65, 0x74, 0x79,
        0x70, 0x65, 0x5c, 0x6d, 0x61, 0x70, 0x6e, 0x61,
        0x6d, 0x65, 0x5c, 0x6e, 0x75, 0x6d, 0x70, 0x6c,
        0x61, 0x79, 0x65, 0x72, 0x73, 0x5c, 0x6d, 0x61,
        0x78, 0x70, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x73,
        0x5c, 0x67, 0x61, 0x6d, 0x65, 0x76, 0x65, 0x72,
        0x5c, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72,
        0x64, 0x5c, 0x68, 0x6f, 0x73, 0x74, 0x70, 0x6f,
        0x72, 0x74, 0x5c, 0x61, 0x6e, 0x74, 0x69, 0x63,
        0x68, 0x65, 0x61, 0x74, 0x5c, 0x6f, 0x66, 0x66,
        0x69, 0x63, 0x69, 0x61, 0x6c, 0x5c, 0x76, 0x6f,
        0x69, 0x63, 0x65, 0x63, 0x6f, 0x6d, 0x6d, 0x5c,
        0x66, 0x72, 0x69, 0x65, 0x6e, 0x64, 0x6c, 0x79,
        0x66, 0x69, 0x72, 0x65, 0x5c, 0x64, 0x78, 0x31,
        0x30, 0x5c, 0x64, 0x65, 0x64, 0x69, 0x63, 0x61,
        0x74, 0x65, 0x64, 0x5c, 0x67, 0x61, 0x6d, 0x65,
        0x70, 0x61, 0x64, 0x73, 0x6f, 0x6e, 0x6c, 0x79,
        0x5c, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x72, 0x79,
        0x5c, 0x6d, 0x6f, 0x64, 0x6e, 0x61, 0x6d, 0x65,
        0x5c, 0x6d, 0x6f, 0x64, 0x76, 0x65, 0x72, 0x73,
        0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00 };
    client->processStream((char*)req1, sizeof(req1));
    printf("sending second request\n");
    unsigned char req2[] = { 0x00, 0x09, 0x01, 0x7F, 0x00, 0x00, 0x01, 0xfa, 0x57 };
    client->processStream((char*)req2, sizeof(req2));
#else
    std::thread master(deployMaster);
    std::thread browser(deployServerBrowser);
#ifdef USE_GC
    std::thread gc(deployGarbageCollector);
#endif
    master.join();
    browser.join();
#ifdef USE_GC
    gc.join();
#endif
#endif
    return 0;
}
