// master.cpp
#define MASTER
#define _CRT_SECURE_NO_WARNINGS
#define DO_LOG
// #define TEST
// #define DEBUG
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
#define SEND_FLAGS MSG_DONTWAIT
#define RECV_FLAGS MSG_DONTWAIT

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

#include "enctypex.h"

typedef std::map<std::string, std::string> Dictionary;

SOCKET master_socket;
SOCKET forwarder_socket;
SOCKET browser_socket;

std::mutex clientMutex;

struct ProxyRequest {
    std::string host;
    std::string script;
    Dictionary params;
};

typedef ProxyRequest *ProxyRequestPtr;

struct ClientInfo;
typedef unsigned long long server_id;
std::map<server_id, ClientInfo *> clients;
void getServers(std::vector<ClientInfo *> &servers, std::string game = "");
ClientInfo *findServer(int ip, int port, std::string game);
void debugOutput(char *buff, int len);
void debugOutputCArray(char *buff, int len);
SOCKET commit_proxy_req(ProxyRequest *req, SOCKET sock);
int masterPort = 9300;

struct ClientInfo {

    // Shared ( Server / Client ):

    int ip;
    int port;
    int sv_port; // !!!Service Port!!!
    int cookie;
    time_t last_recv;
    int packets;
    int traffic_in;
    int traffic_out;
    bool killed;
    bool sent_challenge;

    socklen_t cl;
    sockaddr_in ci;
    std::string game;

    char *outp;
    char *outp_aside;
    char *inp;

    // Client only:

    bool isTcp;
    bool socket_dead;
    bool crypto_sent;
    SOCKET client_sock;
    unsigned char *encxkeyb;
    unsigned char *challenge_str;

    Dictionary params;
    ClientInfo(int a_ip, int a_port, int a_sv_port, sockaddr_in s_in, int s_len, SOCKET sock = 0)
        : ip(a_ip),
          port(a_port),
          last_recv(0),
          packets(0),
          sv_port(a_sv_port),
          client_sock(sock),
          socket_dead(false),
          traffic_in(0),
          traffic_out(0),
          killed(false),
          crypto_sent(false),
          sent_challenge(false) {
        isTcp = sock != 0;
        ci = s_in;
        cl = s_len;
        outp = new char[isTcp ? BROWSER_OUTPUT_BUFFER_SIZE : MASTER_OUTPUT_BUFFER_SIZE];
        inp = isTcp ? new char[4096] : 0;
        encxkeyb = isTcp ? new unsigned char[261] : 0;
        challenge_str = isTcp ? new unsigned char[8] : 0;
        outp_aside = isTcp ? 0 : new char[256];
        if (isTcp) {
            memset(encxkeyb, 0, 261);
            memset(challenge_str, 0, 8);
        }
#ifndef TEST
        if (isTcp) {
            std::thread(ClientInfo::recvThread, this).detach();
        }
#endif
    }
    ~ClientInfo() {
        if (outp) {
            delete[] outp;
            outp = 0;
        }
        if (outp_aside) {
            delete[] outp_aside;
            outp_aside = 0;
        }
        if (inp) {
            delete[] inp;
            inp = 0;
        }
        if (encxkeyb) {
            delete[] encxkeyb;
            encxkeyb = 0;
        }
        if (challenge_str) {
            delete[] challenge_str;
            challenge_str = 0;
        }
        if (isTcp && !socket_dead) {
            CloseSocket(client_sock);
        }
    }
    void requestKill() {
        killed = true;
        if (isTcp) {
            CloseSocket(client_sock);
            socket_dead = true;
        } else {
            last_recv = 0;
        }
    }
    bool isDead() {
        return killed || (isTcp && socket_dead) || (!isTcp && (time(0) - last_recv) > TIMEOUT);
    }
    std::string get(std::string index) {
        Dictionary::iterator it = params.find(index);
        if (it != params.end())
            return it->second;
        return "";
    }
    std::string get(std::string index, int num) {
        Dictionary::iterator it = params.find(index);
        std::string retval = "";
        if (it != params.end())
            retval = it->second;
        if (retval == "")
            retval = std::to_string(num);
        return retval;
    }
    bool has(std::string index) {
        return params.find(index) != params.end();
    }
    server_id getId() {
        return ClientInfo::makeId(ip, port, sv_port);
    }
    std::string getStringIp(int ip = 0) {
        if (ip == 0)
            ip = this->ip;
        return std::to_string((ip >> 24) & 255) + "." +
               std::to_string((ip >> 16) & 255) + "." +
               std::to_string((ip >> 8) & 255) + "." +
               std::to_string((ip)&255);
    }
    ProxyRequestPtr proxifyCrymp() {
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
        crymp["port"] = get("localport");
        crymp["numpl"] = get("numplayers");
        crymp["maxpl"] = get("maxplayers");
        std::string sv_map = get("mapname");
        if (sv_map == "")
            sv_map = "Mesa";
        std::string nmap = "";
        for (auto c : sv_map) {
            if (c != ' ')
                nmap += tolower(c);
        }
        sv_map = nmap;
        // sv_map[0] = sv_map[0] & 0x3F;
        crymp["map"] = std::string("multiplayer/") + std::string((get("gametype") == "InstantAction") ? "ia/" : "ps/") + sv_map;
        crymp["timel"] = get("timeleft");
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
        for (int i = 0; i < numpl; i++) {
            players +=
                std::string("@") + get("player_" + std::to_string(i)) + "%" + get("rank_" + std::to_string(i), 0) + "%" + get("kills_" + std::to_string(i), 0) + "%" + get("deaths_" + std::to_string(i), 0) + "%0" + "%" + get("team_" + std::to_string(i), 0);
        }
        crymp["players"] = players;
        crymp["proxied"] = "1";

        ProxyRequest *pr = new ProxyRequest;
        if (pr) {
            pr->host = "crymp.net";
            pr->script = "/api/up.php";
            pr->params = crymp;
        }
        return pr;
#else
        return 0;
#endif
    }
    void processPacket(char *buff, int packet_len) {
        packets++;
        last_recv = time(0);
        traffic_in += packet_len;
        if (packet_len < 5)
            return;
        char *out = 0;
        if (!outp) {
            printf("[master] [error] failed to process packet, outp is null!!!\n");
            return;
        } else {
            outp[0] = 0xFE;
            outp[1] = 0xFD;
            out = outp + 2;
        }
        char type = buff[0];
        int packet_id = *(int *)(buff + 1);
        char *payload = buff + 5;
        int len = packet_len - 5;
        printf("[master] [info] packet type: %d, packet id: %08X, length: %d\n", type, packet_id, len);
        if (type == MASTER_REGISTER_SERVER && sv_port == MASTER_PORT) {
            game = payload;
            outp[0] = 0xFE;
            outp[1] = 0xFD;
            outp[2] = 0x09;
            for (int i = 0; i < 8; i++)
                outp[i + 3] = 0;
            this->sendUDPResponse(11);
            printf("[master] [msg] subscribed %s:%d to game: %s\n", inet_ntoa(ci.sin_addr), ntohs(ci.sin_port), game.c_str());
        } else if (type == MASTER_UPDATE_SERVER && sv_port == MASTER_PORT) {
            int n = 0;
            std::string key = "";
            std::string val = "";
            this->cookie = packet_id;
            int p_off = 0;
            for (int i = 0; i < len; i++) {
                char c = payload[i];
                if (i > 0 && c == 0 && payload[i - 1] == 0) {
                    p_off = i + 3;
                    break;
                }
                if (c == 0) {
                    if (n % 2 == 1) {
                        params[key] = val;
                        val = "";
                        key = "";
                    }
                    n++;
                } else
                    ((n % 2 == 0) ? key : val) += c;
            }
            std::vector<std::string> indexes;
            int d_off = 0;
            if ((p_off + 5) < packet_len && payload[p_off] == 'p' && payload[p_off - 1] > 0) {
                for (int i = p_off; i < len; i++) {
                    char c = payload[i];
                    if (!c) {
                        if (key.length() == 0) {
                            d_off = i + 1;
                            break;
                        }

                        indexes.push_back(key);
                        key = "";
                    } else {
                        key += c;
                    }
                }
            }
            if (d_off && (d_off + 5) < packet_len && indexes.size()) {
                int ctr = 0;
                for (int i = d_off; i < len; i++) {
                    char c = payload[i];
                    if (!c) {
                        if (val.length() == 0)
                            break;
                        int idx = ctr / indexes.size();
                        std::string item = indexes[ctr % indexes.size()];
                        item += std::to_string(idx);
                        params[item] = val;
                        // printf("item found: %s -> %s\n", item.c_str(), val.c_str());
                        val = "";
                        ctr++;
                    } else {
                        val += c;
                    }
                }
            }
            ClientInfo *existent = findServer(ip, atoi(get("localport").c_str()), game);
            bool existed = false;
            if (existent && existent != this) {
                existent->requestKill();
                existed = true;
            }
            params["country"] = "KP";
            params["publicip"] = std::to_string(ip);
            params["publicport"] = get("localport");
            params["localip"] = get("localip0");
            outp[0] = 0xFE;
            outp[1] = 0xFD;
            outp[2] = 0x01;
            (*(int *)(outp + 3)) = packet_id; // 3 .. 6
            for (int i = 0; i < 21; i++) {
                outp[i + 7] = (rand() % 20) + 65;
            }
            outp[28] = 0;
            if (!sent_challenge)
                this->sendUDPResponse(29);
            sent_challenge = true;
            printf("[master] [msg] updated server %s:%d, killed old: %d\n", inet_ntoa(ci.sin_addr), ntohs(ci.sin_port), existed ? 1 : 0);
            // this->proxifyCrymp();
        } else if (type == MASTER_HEARTBEAT1 || type == MASTER_HEARTBEAT2) {
            outp[0] = 0xFE;
            outp[1] = 0xFD;
            outp[2] = MASTER_HEARTBEAT1 == type ? 0x0A : MASTER_HEARTBEAT2;
            (*(int *)(outp + 3)) = packet_id;
            this->sendUDPResponse(7);
        }
    }
    void processFwdPacket(char *buff, int packet_len) {
        if (packet_len < 5)
            return;
        int type = buff[7];
        if (type == 0) {
            int cl_id = *(int *)(buff + 8);
            int local_ip = *(int *)(buff + 15);
            short local_port = *(short *)(buff + 19);
            memcpy(outp, buff, 21);
            this->sendUDPResponse(21);
        }
    }
    void processStream(char *buff, int stream_len) {
        packets++;
        last_recv = time(0);
        traffic_in += stream_len;
        char dummy1 = buff[0];
        char dummy2 = buff[1];
        char req_type = buff[2];
        if (req_type == BROWSER_SERVER_LIST) {
            char *ptr = buff + 9;
            int len = stream_len - 9;
            char *game = readString(ptr, &len);
            this->game = game;
            char *gamename = readString(ptr, &len);
            char *challenge = ptr;
            // memcpy(challenge_str, challenge, 8);
            for (int i = 0; i < 8; i++)
                challenge_str[i] = challenge[i];
            ptr += 10;
            len -= 10;
            std::vector<std::string> params;
            std::string param = "";
            if (len < 0) {
                printf("[browser] [error] stream seems to be too short!!!\n");
                return;
            }
            for (int i = 0; i < len; i++) {
                if (ptr[i] == '\\' || !ptr[i]) {
                    params.push_back(param);
                    param = "";
                    if (!ptr[i])
                        break;
                } else
                    param += ptr[i];
            }
            ptr += len;

            memset(outp, 0, BROWSER_OUTPUT_BUFFER_SIZE);

            char gamekey[32] = "ZvZDcL";
            int headerLen = 0;
            ptr = prepareCryptoHeader(outp, gamekey, headerLen);

            char *out = ptr;
            ptr = out + 8;
            len = BROWSER_OUTPUT_BUFFER_SIZE - 8;
            for (size_t i = 0; i < params.size(); i++) {
                int pl = params[i].length();
                if (len < pl + 2)
                    break;
                memcpy(ptr, params[i].c_str(), pl + 1);
                ptr += pl + 1;
                ptr[0] = 0;
                ptr++;
                len -= pl + 2;
            }
            if (len > 0) {
                std::vector<ClientInfo *> servers;
                getServers(servers, game);
                for (size_t i = 0; i < servers.size(); i++) {
                    if (len < 14)
                        break;

                    ClientInfo *server = servers[i];
                    if (server->isDead())
                        continue;
                    char type = 0x74;
                    ptr[0] = type;
                    ptr++;

                    ptr[0] = (server->ip >> 24) & 255;
                    ptr[1] = (server->ip >> 16) & 255;
                    ptr[2] = (server->ip >> 8) & 255;
                    ptr[3] = (server->ip) & 255;
                    int inn_port = atoi(server->get("localport").c_str());
                    ptr[4] = (inn_port >> 8) & 255;
                    ptr[5] = (inn_port)&255;
                    ptr += 6;
                    len -= 6;

                    if (type & 0x02) {
                        std::string l_ip = server->get("localip0");
                        int i0, i1, i2, i3;
                        sscanf(l_ip.c_str(), "%d.%d.%d.%d", &i0, &i1, &i2, &i3);
                        ptr[0] = i0;
                        ptr[1] = i1;
                        ptr[2] = i2;
                        ptr[3] = i3;
                        ptr += 4;
                        len -= 4;
                    }

                    if (type & 0x20) {
                        inn_port = atoi(server->get("localport").c_str());
                        ptr[0] = (inn_port >> 8) & 255;
                        ptr[1] = (inn_port)&255;
                        ptr += 2;
                        len -= 2;
                    }

                    printf("[browser] [info] adding server %s to list\n", server->get("hostname").c_str());

                    for (size_t j = 0; j < params.size(); j++) {
                        std::string param = server->get(params[j]);
                        int pl = param.length();
                        if (len < pl + 2)
                            break;
                        ptr[0] = 0xFF;
                        ptr++;
                        if (pl == 0) {
                            ptr[0] = 0x00;
                            ptr++;
                        } else {
                            memcpy(ptr, param.c_str(), pl + 1);
                            ptr += pl + 1;
                        }
                    }
                }

                *ptr = 0x00;
                ptr++;
                ptr[0] = 0xFF;
                ptr[1] = 0xFF;
                ptr[2] = 0xFF;
                ptr[3] = 0xFF;
                ptr += 4;

                len = ptr - outp;

                out[0] = (ip >> 24) & 255;
                out[1] = (ip >> 16) & 255;
                out[2] = (ip >> 8) & 255;
                out[3] = (ip)&255;

                out[4] = (port >> 8) & 255;
                out[5] = port & 255;

                int num = params.size();

                out[7] = (num >> 8) & 255;
                out[6] = (num)&255;

#ifdef DEBUG
                debugOutput(outp, len);
#endif
                enctypex_func6e((unsigned char *)encxkeyb, ((unsigned char *)outp) + headerLen, len - headerLen);

                printf("[browser] [info] sending server list to %016llX, challenge: %016llX / %016llX\n", getId(), *(unsigned long long *)challenge, *(unsigned long long *)challenge_str);

                sendTCPResponse(len);
            }
        } else if (req_type == BROWSER_SERVER_INFO) {
            int sv_ip = ((buff[3] & 0xFF) << 24) | ((buff[4] & 0xFF) << 16) | ((buff[5] & 0xFF) << 8) | ((buff[6] & 0xFF));
            int sv_port = ((buff[7] & 0xFF) << 8) | ((buff[8] & 0xFF));

            printf("[browser] [info] %016llX requesting info about %08X:%04X, game: %s\n", getId(), sv_ip, sv_port, this->game.c_str());
            ClientInfo *server = findServer(sv_ip, sv_port, this->game);
            if (server) {
                memset(outp, 0, BROWSER_OUTPUT_BUFFER_SIZE);
                int headerLen = 0;
                int len = BROWSER_OUTPUT_BUFFER_SIZE - 20;
                char gamekey[32] = "ZvZDcL";
                char *ptr = prepareCryptoHeader(outp, gamekey, headerLen);
                ptr += 20;
                int flags = 0;
                printf("[browser] [info] server found: %s\n", server->get("hostname").c_str());
                fflush(stdout);
                std::vector<std::string> req_params = {
                    "localip", "localport", "natneg", "gamename", "publicip", "publicport",
                    "hostname", "gamever", "hostport", "mapname", "gametype",
                    "numplayers", "maxplayers",
                    "gamemode", "timelimit", "password", "anticheat", "official", "voicecomm",
                    "friendlyfire", "dedicated", "dx10", "gamepadsonly", "timeleft"};
                int numpl = atoi(server->get("numplayers").c_str());
                for (int i = 0; i < numpl; i++) {
                    req_params.push_back("player_" + std::to_string(i));
                    req_params.push_back("team_" + std::to_string(i));
                    req_params.push_back("kills_" + std::to_string(i));
                    req_params.push_back("deaths_" + std::to_string(i));
                    req_params.push_back("rank_" + std::to_string(i));
                }
                for (size_t i = 0; i < req_params.size(); i++) {
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
                    int kl = key.length();
                    int vl = val.length();
                    if (kl == 0)
                        continue;
                    int pl = kl + vl + 2;
                    if (len < pl)
                        break;
                    memcpy(ptr, key.c_str(), kl + 1);
                    ptr += kl + 1;
                    if (vl == 0) {
                        *ptr = 0;
                        ptr++;
                    } else {
                        memcpy(ptr, val.c_str(), vl + 1);
                        ptr += vl + 1;
                    }
                }
                *ptr = 0;
                ptr++;
                len = ptr - outp;

                ptr = outp + headerLen;
                ptr[0] = (len >> 8) & 0xFF;
                ptr[1] = len & 0xFF;
                ptr[2] = 0x02;
                ptr[3] = 0xBE;
                ptr += 4;

                ptr[0] = (server->ip >> 24) & 255;
                ptr[1] = (server->ip >> 16) & 255;
                ptr[2] = (server->ip >> 8) & 255;
                ptr[3] = (server->ip) & 255;
                ptr += 4;

                int inn_port = atoi(server->get("hostport").c_str());
                ptr[0] = (inn_port >> 8) & 255;
                ptr[1] = (inn_port)&255;
                ptr += 2;

                int i0, i1, i2, i3;
                sscanf(server->get("localip0").c_str(), "%d.%d.%d.%d", &i0, &i1, &i2, &i3);
                ptr[0] = i0 & 255;
                ptr[1] = i1 & 255;
                ptr[2] = i2 & 255;
                ptr[3] = i3 & 255;
                ptr += 4;

                inn_port = atoi(server->get("hostport").c_str());
                ptr[0] = (inn_port >> 8) & 255;
                ptr[1] = (inn_port)&255;
                ptr += 2;

                ptr[0] = (server->ip >> 24) & 255;
                ptr[1] = (server->ip >> 16) & 255;
                ptr[2] = (server->ip >> 8) & 255;
                ptr[3] = (server->ip) & 255;
                ptr += 4;

                printf("[browser] [info] sending server info to %016llX, length: %d bytes, challenge: %016llX\n", getId(), len, *(unsigned long long *)challenge_str);
#ifdef DEBUG
                debugOutput(outp, len);
#endif
                printf("INFO: ");
                for (int i = 0; i < len; i++) {
                    printf("%02X", outp[i] & 0xFF);
                }
                printf("\n");
                enctypex_func6e((unsigned char *)encxkeyb, ((unsigned char *)outp) + headerLen, len - headerLen);
                sendTCPResponse(len);
            }
        } else if (req_type == BROWSER_FORWARD) {
            int sv_ip = ((buff[3] & 0xFF) << 24) | ((buff[4] & 0xFF) << 16) | ((buff[5] & 0xFF) << 8) | ((buff[6] & 0xFF));
            int sv_port = ((buff[7] & 0xFF) << 8) | ((buff[8] & 0xFF));
            printf("[browser] [info] %016llX requesting forwarding to %08X:%04X, game: %s\n", getId(), sv_ip, sv_port, this->game.c_str());
            ClientInfo *server = findServer(sv_ip, sv_port, this->game);
            if (server) {
                server->forwardBytes(this, buff + 9, 10);
            }
        }
    }
    int sendUDPResponse(int len, bool sideBuffer = false) {
        traffic_out += len;
#ifdef DEBUG
        debugOutputCArray(sideBuffer ? outp_aside : outp, len);
#endif
        return sendto(sv_port == MASTER_PORT ? master_socket : forwarder_socket, sideBuffer ? outp_aside : outp, len, 0, (sockaddr *)&ci, cl);
    }
    int sendTCPResponse(int len) {
        traffic_out += len;
#ifdef DEBUG
        debugOutputCArray(outp, len);
#endif
        return send(client_sock, outp, len, SEND_FLAGS);
    }
    void forwardBytes(ClientInfo *from, char *buff, int len) {
        if (len > 240)
            len = 240;
        outp_aside[0] = 0xFE;
        outp_aside[1] = 0xFD;
        outp_aside[2] = 0x06;
        memcpy(outp_aside + 3, &cookie, 4);
        for (int i = 0; i < 4; i++)
            outp_aside[i + 6] = rand() & 0xFF;
        memcpy(outp_aside + 10, buff, len);
        sendUDPResponse(len, true);
    }
    static inline server_id makeId(int cl_ip, int cl_port, int svc_port) {
        return (((server_id)svc_port) << 48) | ((((server_id)cl_ip) & 0xFFFFFFFF) << 16) | cl_port;
    }
    static void recvThread(ClientInfo *client) {
        if (!client)
            return;
        printf("[browser] [info] receive thread is active for %016llX\n", client->getId());
        while (true && client) {
            int len = recv(client->client_sock, client->inp, 2048, 0);
            if (len <= 0) {
                client->socket_dead = true;
                CloseSocket(client->client_sock);
                printf("[browser] [info] %016llX received %d bytes, closing (err: %s)\n", client->getId(), len, strerror(errno));
                return;
            } else {
                client->processStream(client->inp, len);
            }
        }
    }
    char *readString(char *&buff, int *len) {
        char *str = buff;
        if (*len <= 0)
            return str;
        int i = 0;
        while (i < *len) {
            if (buff[i] == 0) {
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
    char *prepareCryptoHeader(char *buff, char *gamekey, int &headerLen) {
        if (crypto_sent) {
            headerLen = 0;
            return buff;
        }
        int cryptlen = 10;
        char *ptr = buff;
        unsigned char cryptchal[10] = {0};
        unsigned int servchallen = 25;
        unsigned char servchal[25] = {0};
        headerLen = (servchallen + cryptlen) + (sizeof(unsigned char) * 2);
        unsigned short *backendflags = (unsigned short *)(&cryptchal);
        for (int i = 0; i < cryptlen; i++) {
            cryptchal[i] = (unsigned char)rand();
        }
        *backendflags = htons(BACKEND_FLAGS);
        for (unsigned int i = 0; i < servchallen; i++) {
            servchal[i] = (uint8_t)rand();
        }

        ptr = buff;
        ptr[0] = cryptlen ^ 0xEC;
        ptr++;
        for (int i = 0; i < 10; i++) {
            ptr[i] = cryptchal[i];
        }
        ptr += 10;
        ptr[0] = servchallen ^ 0xEA;
        ptr++;
        for (int i = 0; i < 25; i++) {
            ptr[i] = servchal[i];
        }
        ptr += 25;

        enctypex_funcx((unsigned char *)encxkeyb, (unsigned char *)gamekey, (unsigned char *)challenge_str, (unsigned char *)servchal, servchallen);
        crypto_sent = true;
        return buff + 37;
    }
};

void getServers(std::vector<ClientInfo *> &servers, std::string game) {
    servers.clear();
    clientMutex.lock();
    for (std::map<server_id, ClientInfo *>::iterator it = clients.begin(); it != clients.end(); it++) {
        if (it->second && !it->second->isDead() && it->second->sv_port == MASTER_PORT && !it->second->isTcp && (game.length() == 0 || it->second->get("gamename") == game) && it->second->params.size() > 0)
            servers.push_back(it->second);
    }
    clientMutex.unlock();
}
ClientInfo *findServer(int ip, int port, std::string game) {
    clientMutex.lock();
    for (std::map<server_id, ClientInfo *>::iterator it = clients.begin(); it != clients.end(); it++) {
        if (it->second && !it->second->isDead() && it->second->sv_port == MASTER_PORT && !it->second->isTcp && it->second->get("gamename") == game && it->second->ip == ip && atoi(it->second->get("localport").c_str()) == port) {
            ClientInfo *ci = it->second;
            clientMutex.unlock();
            return ci;
        }
    }
    clientMutex.unlock();
    return 0;
}
void debugOutput(char *p, int len) {
    for (int i = 0; i < len; i++) {
        if (!isalpha(p[i]))
            printf(" %02X ", p[i] & 0xFF);
        else
            printf("%c", p[i]);
    }
    printf("\n\n-----------\n\n");
    fflush(stdout);
}
void debugOutputCArray(char *p, int len) {
    printf("unsigned char buff[%d]={ ", len);
    for (int i = 0; i < len; i++) {
        printf("0x%02X, ", p[i] & 0xFF);
    }
    printf("};\n");
}
int deploy_gc() {
    printf("[gc] garbage collector active\n");
    fflush(stdout);
    while (true) {
        clientMutex.lock();
        for (std::map<server_id, ClientInfo *>::iterator it = clients.begin(); it != clients.end();) {
            ClientInfo *client = it->second;
            if (client && client->isDead()) {
                printf("[gc] [info] removing %016llX for inactivity\n", client->getId());
                delete client;
                it = clients.erase(it);
            } else
                it++;
        }
        clientMutex.unlock();
        Sleep(5000);
    }
}

int deploy_master() {
    printf("[master] [info] initiating master\n");
    fflush(stdout);
    master_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockaddr_in si;
    ZeroMem(si);
    si.sin_family = AF_INET;
    si.sin_port = htons(MASTER_PORT);
    if (bind(master_socket, (sockaddr *)&si, sizeof(si)) < 0) {
        printf("[master] [error] failed to bind to address: %s\n", strerror(errno));
        return 1;
    }
    printf("[master] [info] master online\n");
    fflush(stdout);
    char buffer[2048]; // safe: 2048 > MTU ( 1500 )
    while (true) {
        ClientInfo *client;
        sockaddr_in ci;
        socklen_t cl = sizeof(ci);
        int len = recvfrom(master_socket, buffer, 2048, 0, (sockaddr *)&ci, &cl);
        if (len < 0) {
            printf("[master] [error] failed to receive: %s\n", strerror(errno));
        }
        int ip = ntohl(ci.sin_addr.s_addr);
        int port = ntohs(ci.sin_port);
        server_id id = ClientInfo::makeId(ip, port, MASTER_PORT);
        clientMutex.lock();
        std::map<server_id, ClientInfo *>::iterator it = clients.find(id);
        if (it != clients.end()) {
            client = it->second;
            if (!client) {
                clients.erase(it);
                continue;
            }
            printf("[master] [info] reusing existing client (%016llX)\n", id);
        } else {
            client = new ClientInfo(ip, port, MASTER_PORT, ci, cl);
            if (client) {
                clients[id] = client;
            } else {
                printf("[master] [error] failed to allocate new client!!!\n");
                continue;
            }
            printf("[master] [info] allocated new client (%016llX)\n", id);
        }
        printf("[master] [info] received from %08X:%04X (%016llX) %d bytes\n", ip, port, id, len);
        clientMutex.unlock();
        client->processPacket(buffer, len);
    }
    return 0;
}
int deploy_fwd_service() {
    printf("[forwarder] [info] initiating master\n");
    fflush(stdout);
    forwarder_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockaddr_in si;
    ZeroMem(si);
    si.sin_family = AF_INET;
    si.sin_port = htons(FORWARDER_PORT);
    if (bind(forwarder_socket, (sockaddr *)&si, sizeof(si)) < 0) {
        printf("[forwarder] [error] failed to bind to address: %s\n", strerror(errno));
        return 1;
    }
    printf("[forwarder] [info] master online\n");
    fflush(stdout);
    char buffer[2048]; // safe: 2048 > MTU ( 1500 )
    while (true) {
        ClientInfo *client;
        sockaddr_in ci;
        socklen_t cl = sizeof(ci);
        int len = recvfrom(forwarder_socket, buffer, 2048, 0, (sockaddr *)&ci, &cl);
        if (len < 0) {
            printf("[forwarder] [error] failed to receive: %s\n", strerror(errno));
        }
        int ip = ntohl(ci.sin_addr.s_addr);
        int port = ntohs(ci.sin_port);
        server_id id = ClientInfo::makeId(ip, port, FORWARDER_PORT);
        clientMutex.lock();
        std::map<server_id, ClientInfo *>::iterator it = clients.find(id);
        if (it != clients.end()) {
            client = it->second;
            if (!client) {
                clients.erase(it);
                continue;
            }
            printf("[master] [info] reusing existing client (%016llX)\n", id);
        } else {
            client = new ClientInfo(ip, port, FORWARDER_PORT, ci, cl);
            if (client) {
                clients[id] = client;
            } else {
                printf("[master] [error] failed to allocate new client!!!\n");
                continue;
            }
            printf("[master] [info] allocated new client (%016llX)\n", id);
        }
        printf("[master] [info] received from %08X:%04X (%016llX) %d bytes\n", ip, port, id, len);
        clientMutex.unlock();
        client->processFwdPacket(buffer, len);
    }
    return 0;
}
int deploy_server_browser() {
    printf("[browser] [info] initiating server browser\n");
    fflush(stdout);
    browser_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

#ifndef _WIN32
    int optval = 1;
    setsockopt(browser_socket, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval, sizeof(int));
#endif

    sockaddr_in si;
    ZeroMem(si);
    si.sin_family = AF_INET;
    si.sin_port = htons(BROWSER_PORT);
    if (bind(browser_socket, (sockaddr *)&si, sizeof(si)) < 0) {
        printf("[browser] [error] failed to bind to address: %s\n", strerror(errno));
        return 1;
    }
    listen(browser_socket, 800);
    while (true) {
        sockaddr_in ci;
        socklen_t cl = sizeof(ci);
        SOCKET client_sock = accept(browser_socket, (sockaddr *)&ci, &cl);
        if (client_sock < 0) {
            printf("[browser] [error] failed to accept: %s\n", strerror(errno));
            continue;
        }

        struct timeval tv;
        tv.tv_sec = TIMEOUT;
        tv.tv_usec = 0;
        setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);

        int ip = ntohl(ci.sin_addr.s_addr);
        int port = ntohs(ci.sin_port);
        server_id id = ClientInfo::makeId(ip, port, BROWSER_PORT);
        clientMutex.lock();
        std::map<server_id, ClientInfo *>::iterator it = clients.find(id);
        ClientInfo *client = 0;
        if (it != clients.end()) {
            printf("[browser] [info] reusing existing client (%016llX)\n", id);
            client = it->second;
        } else {
            client = new ClientInfo(ip, port, BROWSER_PORT, ci, cl, client_sock);
            if (client) {
                clients[id] = client;
                printf("[browser] [info] allocated new client (%016llX)\n", id);
            } else
                printf("[browser] [error] failed to allocate new client!!!\n");
        }
        clientMutex.unlock();
    }
    return 0;
}

std::string urlencode(std::string str) {
    std::string n = "";
    static char hex[17] = "0123456789ABCDEF";
    for (auto c : str) {
        if (!isalnum(c)) {
            n += "%";
            n += hex[(c >> 4) & 0xF];
            n += hex[c & 0xF];
        } else
            n += c;
    }
    return n;
}

SOCKET commit_proxy_req(ProxyRequest *req, SOCKET sock) {
    printf("[proxy] [info] proxying request for %s (%s:%s)\n", req->params["name"].c_str(), req->params["proxy_ip"].c_str(), req->params["port"].c_str());
    std::string data = "POST " + req->script + " HTTP/1.1\r\nHost: " + req->host + "\r\nContent-type: application/x-www-form-urlencoded\r\nConnection: keep-alive\r\nContent-length: ";
    std::string query = "";
    bool first = true;
    for (auto &it : req->params) {
        if (!first)
            query += "&";
        query += it.first + "=" + urlencode(it.second);
        first = false;
    }
    data += std::to_string(query.length()) + "\r\n\r\n" + query;

    SOCKET s = 0;
    if (sock)
        s = sock;
    else
        s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (!sock) {
        hostent *h = gethostbyname(req->host == "crymp.net" ? "localhost" : req->host.c_str());
        if (h) {
            sockaddr_in ci;
            in_addr *ip = (in_addr *)h->h_addr;
            ZeroMem(ci);
            ci.sin_addr = *ip;
            ci.sin_port = htons(masterPort);
            ci.sin_family = AF_INET;
            if (connect(s, (const sockaddr *)&ci, sizeof(ci)) == 0) {
                sock = s;
            } else
                return 0;
        } else
            return 0;
    }
    send(sock, data.c_str(), data.length(), 0);
    static char bf[8];
    recv(sock, bf, sizeof(bf), 0);
    return sock;
}

void proxy_dispatcher() {
    while (true) {
        std::vector<ClientInfo *> servers;
        getServers(servers, "crysis");
        SOCKET sock = 0;
        for (auto &it : servers) {
            ProxyRequestPtr req = it->proxifyCrymp();
            if (req) {
                req->host = "crymp.net";
                sock = commit_proxy_req(req, sock);
                delete req;
            }
        }
        if (sock) {
            CloseSocket(sock);
            sock = 0;
        }
        Sleep(45000);
    }
}

int main(int argc, const char **argv) {
    for (int i = 0; i < argc - 1; i++) {
        if (strcmp(argv[i], "-p") == 0) {
            masterPort = atoi(argv[i + 1]);
        }
    }
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(0x202, &wsaData);
#endif
#ifdef PROXY_ENABLED
    std::thread proxyThread(proxy_dispatcher);
    proxyThread.detach();
#endif
#ifdef TEST
    sockaddr_in si;
    ZeroMem(si);
    for (int i = 0; i < 2; i++) {
        ClientInfo *server = new ClientInfo(INADDR_LOOPBACK, 21330 + i, MASTER_PORT, si, 0, 0);
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

    ClientInfo *client = new ClientInfo(INADDR_LOOPBACK, 5004, BROWSER_PORT, si, 0, 1);
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
        0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00};
    client->processStream((char *)req1, sizeof(req1));
    unsigned char req2[] = {0x00, 0x09, 0x01, 0x7F, 0x00, 0x00, 0x01, 0xfa, 0x57};
    client->processStream((char *)req2, sizeof(req2));
#ifdef _WIN32
    getchar();
#endif
#else
    std::thread master(deploy_master);
    std::thread browser(deploy_server_browser);
#ifdef USE_GC
    std::thread gc(deploy_gc);
#endif
    master.join();
    browser.join();
#ifdef USE_GC
    gc.join();
#endif
#endif
    return 0;
}
