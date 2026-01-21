#include "filesystem_base.h" // Has to be before symbols.h
#include "LuaInterface.h"
#include "detours.h"
#include "module.h"
#include "lua.h"
#include "tier0/threadtools.h"
#include "sourcesdk/baseserver.h"
#include "sourcesdk/cnetchan.h"
#include <atomic>
#include <memory>
#include <mutex>
#include "sourcesdk/proto_oob.h"
#include "steam/steam_gameserver.h"
#include <eiface.h>

// memdbgon must be the last include file in a .cpp file!!!
#include "tier0/memdbgon.h"
#include <netadr_new.h>

/*
	Current purpose:
	We currently handle receiving and filtering packages on a different thread
	allowing the main thread to have less work as it only now has to work off already confirmed packets
	instead of having first to receive all of them and filter them.
*/
class CNetworkThreadingModule : public IModule
{
public:
	void InitDetour(bool bPreServer) override;
	void ServerActivate(edict_t* pEdictList, int edictCount, int clientMax) override;
	void LevelShutdown() override;
	void Think(bool bSimulating) override;
	const char* Name() override { return "networkthreading"; };
	int Compatibility() override { return LINUX32; };
	bool IsEnabledByDefault() override { return true; };
};

static CNetworkThreadingModule g_pNetworkThreadingModule;
IModule* pNetworkThreadingModule = &g_pNetworkThreadingModule;

static ConVar networkthreading_parallelprocessing("holylib_networkthreading_parallelprocessing", "0", 0, "If enabled, some packets will be processed by the networking thread instead of the main thread");
static ConVar networkthreading_forcechallenge("holylib_networkthreading_forcechallenge", "0", 0, "If enabled, clients are ALWAYS requested to have a challenge for A2S requests.");

// Query response customization
static ConVar networkthreading_queryresponse("holylib_networkthreading_queryresponse", "0", 0, "If enabled, A2S_INFO responses can be customized via the HolyLib_QueryResponse hook");
static ConVar networkthreading_queryresponse_cachetime("holylib_networkthreading_queryresponse_cachetime", "5", 0, "How often (in seconds) the query response cache is rebuilt");
static ConVar networkthreading_queryresponse_luahook("holylib_networkthreading_queryresponse_luahook", "0", 0, "If enabled, the HolyLib_QueryResponse Lua hook is called when rebuilding the cache");

// Thread-safe query response cache
static std::shared_mutex g_pQueryResponseMutex;
static char g_pQueryResponseBuffer[1024];
static bf_write g_pQueryResponsePacket(g_pQueryResponseBuffer, sizeof(g_pQueryResponseBuffer));
static std::atomic<bool> g_bQueryResponseValid = false;
static std::atomic<float> g_flQueryResponseLastUpdate = 0.0f;
static std::atomic<bool> g_bQueryResponseNeedsRebuild = true;

// Cached ConVar values for network thread (avoid ConVar::GetBool() overhead in hot path)
static std::atomic<bool> g_bQueryResponseEnabled = false;
static std::atomic<float> g_flQueryResponseCacheTime = 5.0f;

// Static info that doesn't change per-map
static std::string g_strGameDir;
static std::string g_strGameDesc;
static std::string g_strGameVersion;
static int32_t g_nMaxClients = 0;
static int32_t g_nUDPPort = 0;

// NOTE: There is inside gcsteamdefines.h the AUTO_LOCK_WRITE which we could probably use
//static CThreadRWLock g_pIPFilterMutex; // Idk if using a std::shared_mutex might be faster
static std::shared_mutex g_pIPFilterMutex; // Using it now since the CThreadRWLock caused linker issues and I don't have the nerves rn to deal with that crap
static Symbols::Filter_ShouldDiscard func_Filter_ShouldDiscard;
static bool Filter_ShouldDiscard(const netadr_t& adr)
{
	std::shared_lock<std::shared_mutex> readLock(g_pIPFilterMutex);

	if (func_Filter_ShouldDiscard)
		return func_Filter_ShouldDiscard(adr);

	return false;
}

static Detouring::Hook detour_Filter_Add_f;
static void hook_Filter_Add_f(const CCommand* pCommand)
{
	std::unique_lock<std::shared_mutex> writeLock(g_pIPFilterMutex);
	
	detour_Filter_Add_f.GetTrampoline<Symbols::Filter_Add_f>()(pCommand);
}

static Detouring::Hook detour_removeip;
static void hook_removeip(const CCommand* pCommand)
{
	std::unique_lock<std::shared_mutex> writeLock(g_pIPFilterMutex);

	detour_removeip.GetTrampoline<Symbols::removeip>()(pCommand);
}

static Detouring::Hook detour_writeip;
static void hook_writeip(const CCommand* pCommand)
{
	std::unique_lock<std::shared_mutex> writeLock(g_pIPFilterMutex);

	detour_writeip.GetTrampoline<Symbols::writeip>()(pCommand);
}

static Detouring::Hook detour_listip;
static void hook_listip(const CCommand* pCommand)
{
	// read lock since it doesn't modify it.
	std::shared_lock<std::shared_mutex> readLock(g_pIPFilterMutex);

	detour_listip.GetTrampoline<Symbols::listip>()(pCommand);
}

struct QueuedPacket {
	~QueuedPacket()
	{
		if (pBytes)
		{
			delete[] pBytes;
			pBytes = nullptr;
		}

		if (g_pNetworkThreadingModule.InDebug() == 1)
			Msg(PROJECT_NAME " - networkthreading: Freeing %i bytes after packet was now processed (%p)\n", pPacket.size, this);
	}

	netpacket_s pPacket;
	bool bIsConnectionless = false;
	unsigned char* pBytes = nullptr;
};

static CThreadMutex g_pQueuePacketsMutex;
static std::vector<QueuedPacket*> g_pQueuedPackets;
static inline void AddPacketToQueueForMainThread(netpacket_s* pPacket, bool bIsConnectionless)
{
	if (pPacket->size > NET_MAX_MESSAGE)
	{
		char pNetAddr[64]; // Needed since else .ToString is not threadsafe!
		(*(netadrnew_s*)&pPacket->from).ToString(pNetAddr, sizeof(pNetAddr), false);
		ConDMsg(PROJECT_NAME " - networkthreading: Unholy Packet size from %s (%i/%i) dropping!\n", pNetAddr, pPacket->size, NET_MAX_MESSAGE);
		return;
	}

	QueuedPacket* pQueue = new QueuedPacket();
	pQueue->pPacket = *pPacket;
	pQueue->bIsConnectionless = bIsConnectionless;
	pQueue->pBytes = new unsigned char[pPacket->size];
	memcpy(pQueue->pBytes, pPacket->data, pPacket->size);

	pQueue->pPacket.data = pQueue->pBytes; // Update the pointer for later access
	pQueue->pPacket.message.StartReading( pQueue->pPacket.data, pQueue->pPacket.size, pPacket->message.GetNumBitsRead() ); // also needs updating
	pQueue->pPacket.pNext = nullptr;

	if (g_pNetworkThreadingModule.InDebug() == 1)
		Msg(PROJECT_NAME " - networkthreading: Added %i bytes packet to queue (%p)\n", pPacket->size, pQueue);

	AUTO_LOCK(g_pQueuePacketsMutex);
	g_pQueuedPackets.push_back(pQueue);
}

enum HandleStatus
{
	QUEUE_TO_MAIN, // Queues the packet to be processed by the main thread
	HANDLE_NOW, // Handles the packet in our network thread
	DISCARD, // Discards the packet as it probably has junk
};

// Returning false will result in the packet being put into the queue and let for the main thread to handle.
static inline HandleStatus ShouldHandlePacket(netpacket_s* pPacket, bool isConnectionless)
{
	if (isConnectionless)
	{
		bf_read msg = pPacket->message;
		char c = (char)msg.ReadChar();
		if (c == 0) // Junk
			return HandleStatus::DISCARD;

		if (networkthreading_parallelprocessing.GetBool())
		{
			if (c == A2S_GETCHALLENGE || c == A2S_SERVERQUERY_GETCHALLENGE || c == A2S_INFO || c == A2S_PLAYER || c == A2S_RULES)
			{
				return HandleStatus::HANDLE_NOW;
			}
		}
	}

	// For now we just do the receiving and filtering.
	// We don't allow any specific packets yet to be processed threaded.
	return HandleStatus::QUEUE_TO_MAIN;
}

#if MODULE_EXISTS_GAMESERVER
extern ConVar sv_filter_nobanresponse;
#endif

enum NetworkThreadState
{
	STATE_NOTRUNNING,
	STATE_RUNNING,
	STATE_SHOULD_SHUTDOWN,
};

// BUG: GMod's CBaseServer::GetChallengeNr isn't thread safe
static std::atomic<uint32> g_nChallengeNr = 0;
static Symbols::NET_SendPacket func_NET_SendPacket = nullptr;
static inline void SendChallenge(netpacket_s* pPacket)
{
	uint64 challenge = ((uint64)pPacket->from.GetIPNetworkByteOrder() << 32) + g_nChallengeNr.load();
	CRC32_t hash;
	CRC32_Init(&hash);
	CRC32_ProcessBuffer(&hash, &challenge, sizeof(challenge));
	CRC32_Final(&hash);
	int challengeNr = (int)hash;

	CBaseServer* pServer = (CBaseServer*)Util::server;

	ALIGN4 char buffer[16] ALIGN4_POST;
	bf_write msg(buffer,sizeof(buffer));
	msg.WriteLong(CONNECTIONLESS_HEADER);
	msg.WriteByte(S2C_CHALLENGE);
	msg.WriteLong(challengeNr);
	func_NET_SendPacket(NULL, pServer->m_Socket, pPacket->from, msg.GetData(), msg.GetNumBytesWritten(), nullptr, false);
}

static inline bool EnforceConnectionlessChallenge(netpacket_s* pPacket)
{
	if (!networkthreading_forcechallenge.GetBool() || !func_NET_SendPacket)
		return false;

	char c = (char)pPacket->message.ReadChar();
	if (c == A2S_INFO)
	{
		constexpr int payload = sizeof("Source Engine Query\0") * 8;
		if (!pPacket->message.SeekRelative(payload))
			return false;
	} else {
		if (c != A2S_PLAYER && c != A2S_RULES)
			return false;
	}

	// Now it can only be A2S_INFO, A2S_PLAYER, A2S_RULES
	long challenge = pPacket->message.ReadLong();
	if (challenge == 0xFFFFFFFF)
	{
		SendChallenge(pPacket);
		return true;
	}
}

static std::atomic<int> g_nThreadState = NetworkThreadState::STATE_NOTRUNNING;
static Symbols::NET_GetPacket func_NET_GetPacket;
static Symbols::Filter_SendBan func_Filter_SendBan;
static Symbols::NET_FindNetChannel func_NET_FindNetChannel;

// Query response cache - called from network thread (HOT PATH - highly optimized)
static inline bool SendCachedQueryResponse(netpacket_s* pPacket, int nSocket)
{
	// Fast path: check atomics only (no ConVar access, no pointer derefs)
	if (!g_bQueryResponseValid.load(std::memory_order_relaxed))
		return false;

	// Read lock for thread-safe cache access
	std::shared_lock<std::shared_mutex> readLock(g_pQueryResponseMutex);

	func_NET_SendPacket(NULL, nSocket, pPacket->from,
		g_pQueryResponsePacket.GetData(), g_pQueryResponsePacket.GetNumBytesWritten(), nullptr, false);

	return true;
}

// Called from main thread to rebuild the query response cache
static void BuildQueryResponseCache()
{
	if (!Util::server || !Util::engineserver)
		return;

	CBaseServer* pServer = (CBaseServer*)Util::server;

	// Use std::string for values that may come from Lua (string lifetime safety)
	std::string server_name = pServer->GetName();
	std::string map_name = pServer->GetMapName();
	std::string game_dir = g_strGameDir;
	std::string game_desc = g_strGameDesc;
	std::string game_version = g_strGameVersion;
	std::string tags;

	int32_t appid = Util::engineserver->GetAppID();
	int32_t num_clients = pServer->GetNumClients();
	int32_t num_fake_clients = pServer->GetNumFakeClients();
	bool has_password = pServer->GetPassword() != nullptr;
	int32_t udp_port = g_nUDPPort;
	uint64_t steamid = 0;

	// Check sv_visiblemaxplayers like serversecure/fastquery
	static ConVarRef sv_visiblemaxplayers("sv_visiblemaxplayers");
	int32_t max_players = sv_visiblemaxplayers.IsValid() ? sv_visiblemaxplayers.GetInt() : -1;
	if (max_players <= 0 || max_players > g_nMaxClients)
		max_players = g_nMaxClients;

	// Get Steam info if available
	bool vac_secure = false;
	ISteamGameServer* pGameServer = SteamGameServer();
	if (pGameServer)
		vac_secure = pGameServer->BSecure();

	const CSteamID* pSteamID = Util::engineserver->GetGameServerSteamID();
	if (pSteamID)
		steamid = pSteamID->ConvertToUint64();

	// Call Lua hook if enabled (main thread only)
	if (networkthreading_queryresponse_luahook.GetBool() && g_Lua)
	{
		g_Lua->GetField(GarrysMod::Lua::INDEX_GLOBAL, "hook");
		if (g_Lua->IsType(-1, GarrysMod::Lua::Type::Table))
		{
			g_Lua->GetField(-1, "Run");
			g_Lua->Remove(-2);
			if (g_Lua->IsType(-1, GarrysMod::Lua::Type::Function))
			{
				g_Lua->PushString("HolyLib_QueryResponse");

				// Push info table
				g_Lua->CreateTable();

				g_Lua->PushString(server_name.c_str());
				g_Lua->SetField(-2, "server_name");

				g_Lua->PushString(map_name.c_str());
				g_Lua->SetField(-2, "map_name");

				g_Lua->PushString(game_dir.c_str());
				g_Lua->SetField(-2, "game_dir");

				g_Lua->PushString(game_desc.c_str());
				g_Lua->SetField(-2, "game_desc");

				g_Lua->PushNumber(appid);
				g_Lua->SetField(-2, "appid");

				g_Lua->PushNumber(num_clients);
				g_Lua->SetField(-2, "num_clients");

				g_Lua->PushNumber(max_players);
				g_Lua->SetField(-2, "max_players");

				g_Lua->PushNumber(num_fake_clients);
				g_Lua->SetField(-2, "num_fake_clients");

				g_Lua->PushBool(has_password);
				g_Lua->SetField(-2, "has_password");

				g_Lua->PushBool(vac_secure);
				g_Lua->SetField(-2, "vac_secure");

				g_Lua->PushString(game_version.c_str());
				g_Lua->SetField(-2, "game_version");

				g_Lua->PushNumber(udp_port);
				g_Lua->SetField(-2, "udp_port");

				g_Lua->PushNumber(static_cast<double>(steamid));
				g_Lua->SetField(-2, "steamid");

				g_Lua->PushString(tags.c_str());
				g_Lua->SetField(-2, "tags");

				if (g_Lua->PCall(2, 1, 0) == 0)
				{
					// Read ALL modified values from returned table (like fastquery)
					if (g_Lua->IsType(-1, GarrysMod::Lua::Type::Table))
					{
						g_Lua->GetField(-1, "server_name");
						if (g_Lua->IsType(-1, GarrysMod::Lua::Type::String))
							server_name = g_Lua->GetString(-1);
						g_Lua->Pop(1);

						g_Lua->GetField(-1, "map_name");
						if (g_Lua->IsType(-1, GarrysMod::Lua::Type::String))
							map_name = g_Lua->GetString(-1);
						g_Lua->Pop(1);

						g_Lua->GetField(-1, "game_dir");
						if (g_Lua->IsType(-1, GarrysMod::Lua::Type::String))
							game_dir = g_Lua->GetString(-1);
						g_Lua->Pop(1);

						g_Lua->GetField(-1, "game_desc");
						if (g_Lua->IsType(-1, GarrysMod::Lua::Type::String))
							game_desc = g_Lua->GetString(-1);
						g_Lua->Pop(1);

						g_Lua->GetField(-1, "appid");
						if (g_Lua->IsType(-1, GarrysMod::Lua::Type::Number))
							appid = static_cast<int32_t>(g_Lua->GetNumber(-1));
						g_Lua->Pop(1);

						g_Lua->GetField(-1, "num_clients");
						if (g_Lua->IsType(-1, GarrysMod::Lua::Type::Number))
							num_clients = static_cast<int32_t>(g_Lua->GetNumber(-1));
						g_Lua->Pop(1);

						g_Lua->GetField(-1, "max_players");
						if (g_Lua->IsType(-1, GarrysMod::Lua::Type::Number))
							max_players = static_cast<int32_t>(g_Lua->GetNumber(-1));
						g_Lua->Pop(1);

						g_Lua->GetField(-1, "num_fake_clients");
						if (g_Lua->IsType(-1, GarrysMod::Lua::Type::Number))
							num_fake_clients = static_cast<int32_t>(g_Lua->GetNumber(-1));
						g_Lua->Pop(1);

						g_Lua->GetField(-1, "has_password");
						if (g_Lua->IsType(-1, GarrysMod::Lua::Type::Bool))
							has_password = g_Lua->GetBool(-1);
						g_Lua->Pop(1);

						g_Lua->GetField(-1, "vac_secure");
						if (g_Lua->IsType(-1, GarrysMod::Lua::Type::Bool))
							vac_secure = g_Lua->GetBool(-1);
						g_Lua->Pop(1);

						g_Lua->GetField(-1, "game_version");
						if (g_Lua->IsType(-1, GarrysMod::Lua::Type::String))
							game_version = g_Lua->GetString(-1);
						g_Lua->Pop(1);

						g_Lua->GetField(-1, "udp_port");
						if (g_Lua->IsType(-1, GarrysMod::Lua::Type::Number))
							udp_port = static_cast<int32_t>(g_Lua->GetNumber(-1));
						g_Lua->Pop(1);

						g_Lua->GetField(-1, "steamid");
						if (g_Lua->IsType(-1, GarrysMod::Lua::Type::Number))
							steamid = static_cast<uint64_t>(g_Lua->GetNumber(-1));
						g_Lua->Pop(1);

						g_Lua->GetField(-1, "tags");
						if (g_Lua->IsType(-1, GarrysMod::Lua::Type::String))
							tags = g_Lua->GetString(-1);
						g_Lua->Pop(1);
					}
				}
				else
				{
					// PCall failed, log error
					if (g_Lua->IsType(-1, GarrysMod::Lua::Type::String))
						ConDMsg(PROJECT_NAME " - networkthreading: HolyLib_QueryResponse hook error: %s\n", g_Lua->GetString(-1));
				}
				g_Lua->Pop(1);
			}
			else
			{
				g_Lua->Pop(1);
			}
		}
		else
		{
			g_Lua->Pop(1);
		}
	}

	// Build the packet with write lock (all strings are now safely copied)
	{
		std::unique_lock<std::shared_mutex> writeLock(g_pQueryResponseMutex);

		bool has_tags = !tags.empty();

		g_pQueryResponsePacket.Reset();
		g_pQueryResponsePacket.WriteLong(-1);  // Connectionless header
		g_pQueryResponsePacket.WriteByte('I'); // A2S_INFO response
		g_pQueryResponsePacket.WriteByte(17);  // Protocol version
		g_pQueryResponsePacket.WriteString(server_name.c_str());
		g_pQueryResponsePacket.WriteString(map_name.c_str());
		g_pQueryResponsePacket.WriteString(game_dir.c_str());
		g_pQueryResponsePacket.WriteString(game_desc.c_str());
		g_pQueryResponsePacket.WriteShort(static_cast<short>(appid));
		g_pQueryResponsePacket.WriteByte(static_cast<unsigned char>(num_clients));
		g_pQueryResponsePacket.WriteByte(static_cast<unsigned char>(max_players));
		g_pQueryResponsePacket.WriteByte(static_cast<unsigned char>(num_fake_clients));
		g_pQueryResponsePacket.WriteByte('d'); // Dedicated server
#ifdef _WIN32
		g_pQueryResponsePacket.WriteByte('w'); // Windows
#else
		g_pQueryResponsePacket.WriteByte('l'); // Linux
#endif
		g_pQueryResponsePacket.WriteByte(has_password ? 1 : 0);
		g_pQueryResponsePacket.WriteByte(vac_secure ? 1 : 0);
		g_pQueryResponsePacket.WriteString(game_version.c_str());

		// EDF (Extra Data Flag)
		// 0x80 - port number is present
		// 0x10 - server steamid is present
		// 0x20 - tags are present
		// 0x01 - game long appid is present
		uint8_t edf = 0x80 | 0x10 | (has_tags ? 0x20 : 0x00) | 0x01;
		g_pQueryResponsePacket.WriteByte(edf);
		g_pQueryResponsePacket.WriteShort(static_cast<short>(udp_port));
		g_pQueryResponsePacket.WriteLongLong(static_cast<int64_t>(steamid));
		if (has_tags)
			g_pQueryResponsePacket.WriteString(tags.c_str());
		g_pQueryResponsePacket.WriteLongLong(static_cast<int64_t>(appid));

		g_bQueryResponseValid.store(true);
	}

	g_flQueryResponseLastUpdate.store(static_cast<float>(Plat_FloatTime()));
	g_bQueryResponseNeedsRebuild.store(false);
}

// Initialize static query response info
static void InitQueryResponseInfo()
{
	if (!Util::server || !Util::engineserver || !Util::servergamedll)
		return;

	CBaseServer* pServer = (CBaseServer*)Util::server;

	// Get game directory
	char szGameDir[256];
	Util::engineserver->GetGameDir(szGameDir, sizeof(szGameDir));
	g_strGameDir = szGameDir;
	size_t pos = g_strGameDir.find_last_of("\\/");
	if (pos != std::string::npos)
		g_strGameDir.erase(0, pos + 1);

	// Get game description
	g_strGameDesc = Util::servergamedll->GetGameDescription();

	// Get max clients and port
	g_nMaxClients = pServer->GetMaxClients();
	g_nUDPPort = pServer->GetUDPPort();

	// Get game version from steam.inf
	g_strGameVersion = "2.0.0.0";
	FileHandle_t file = g_pFullFileSystem->Open("steam.inf", "r", "GAME");
	if (file)
	{
		char buff[256];
		if (g_pFullFileSystem->ReadLine(buff, sizeof(buff), file))
		{
			// Line format: PatchVersion=2.X.X.X
			if (strlen(buff) > 13)
			{
				g_strGameVersion = &buff[13];
				size_t endpos = g_strGameVersion.find_first_of("\r\n");
				if (endpos != std::string::npos)
					g_strGameVersion.erase(endpos);
			}
		}
		g_pFullFileSystem->Close(file);
	}

	g_bQueryResponseNeedsRebuild.store(true);
}

static SIMPLETHREAD_RETURNVALUE NetworkThread(void* pThreadData)
{
	if (!Util::server || !func_NET_GetPacket || !func_Filter_SendBan || !func_NET_FindNetChannel)
	{
		Msg(PROJECT_NAME " - networkthreading: Shutting down thread since were missing some functions!\n");
		g_nThreadState.store(NetworkThreadState::STATE_NOTRUNNING);
		return 0;
	}

	CBaseServer* pServer = (CBaseServer*)Util::server;
	int nSocket = pServer->m_Socket;

	std::unique_ptr<unsigned char[]> pScratchBuffer(new unsigned char[NET_MAX_MESSAGE]);
	unsigned char* pBuffer = pScratchBuffer.get();

	ConVarRef net_showudp("net_showudp");

	netpacket_s* packet;
	while (g_nThreadState.load() == NetworkThreadState::STATE_RUNNING)
	{
		while ((packet = func_NET_GetPacket(nSocket, pBuffer)) != nullptr)
		{
			if (Filter_ShouldDiscard(packet->from)) // filtering is done by network layer
			{
#if MODULE_EXISTS_GAMESERVER
				if (!sv_filter_nobanresponse.GetBool())
#endif
				{
					func_Filter_SendBan(packet->from); // tell them we aren't listening...
				}
				continue;
			} 

			// check for connectionless packet (0xffffffff) first
			if (LittleLong(*(unsigned int *)packet->data) == CONNECTIONLESS_HEADER)
			{
				packet->message.ReadLong();	// read the -1
				if (EnforceConnectionlessChallenge(packet))
					continue;

				// Check if this is an A2S_INFO request and we should send cached response
				// Uses cached atomics for ConVar values (avoid ConVar::GetBool() in hot path)
				if (g_bQueryResponseEnabled.load(std::memory_order_relaxed) && packet->size >= 5)
				{
					char queryType = packet->data[4];
					if (queryType == A2S_INFO)
					{
						// Check if cache is valid and send cached response
						if (SendCachedQueryResponse(packet, nSocket))
						{
							// Flag that cache should be rebuilt if enough time passed
							float timeSinceUpdate = static_cast<float>(Plat_FloatTime()) - g_flQueryResponseLastUpdate.load(std::memory_order_relaxed);
							if (timeSinceUpdate >= g_flQueryResponseCacheTime.load(std::memory_order_relaxed))
								g_bQueryResponseNeedsRebuild.store(true, std::memory_order_relaxed);

							continue; // We handled it
						}
					}
				}

				if (net_showudp.GetInt())
					Msg("UDP <- %s: sz=%i OOB '%c' wire=%i\n", packet->from.ToString(), packet->size, packet->data[4], packet->wiresize);

				HandleStatus pStatus = ShouldHandlePacket(packet, true);
				if (pStatus == HandleStatus::DISCARD)
					continue;

				if (pStatus == HandleStatus::HANDLE_NOW) {
					pServer->ProcessConnectionlessPacket(packet);
				} else {
					AddPacketToQueueForMainThread(packet, true);
				}
				continue;
			}

			// check for packets from connected clients
			CNetChan* netchan = func_NET_FindNetChannel(nSocket, packet->from);
			if (netchan)
			{
				HandleStatus pStatus = ShouldHandlePacket(packet, false);
				if (pStatus == HandleStatus::HANDLE_NOW) {
					netchan->ProcessPacket(packet, true);
				} else {
					AddPacketToQueueForMainThread(packet, false);
				}
			} else {
				char pNetAddr[64]; // Needed since else .ToString is not threadsafe!
				(*(netadrnew_s*)&packet->from).ToString(pNetAddr, sizeof(pNetAddr), false);
				if (g_pNetworkThreadingModule.InDebug() == 1)
					Msg(PROJECT_NAME " - networkthreading: Discarding of %i bytes since there is no channel for %s!\n", packet->size, pNetAddr);
			}
		}

		ThreadSleep(1); // hoping to not make it use like 100% CPU without slowing down networking
	}

	g_nThreadState.store(NetworkThreadState::STATE_NOTRUNNING);
	return 0;
}

static Detouring::Hook detour_NET_ProcessSocket;
static std::unordered_set<INetChannel*> g_pNetChannels; // No mutex since only the main thread parties on it... hopefully
static void hook_NET_ProcessSocket(int nSocket, IConnectionlessPacketHandler* pHandler)
{
	if (!Util::server || nSocket != ((CBaseServer*)Util::server)->m_Socket || g_nThreadState.load() == NetworkThreadState::STATE_NOTRUNNING)
	{
		detour_NET_ProcessSocket.GetTrampoline<Symbols::NET_ProcessSocket>()(nSocket, pHandler);
		return;
	}

	VPROF_BUDGET("HolyLib - NET_ProcessSocket", VPROF_BUDGETGROUP_HOLYLIB);

	// get streaming data from channel sockets
	// NOTE: This code is probably completely useless since Gmod doesn't use TCP
	for(INetChannel* netchan : g_pNetChannels)
	{
		// sockets must match
		if (nSocket != netchan->GetSocket())
			continue;

		if (!netchan->ProcessStream())
			netchan->GetMsgHandler()->ConnectionCrashed("TCP connection failed.");
	}

	AUTO_LOCK(g_pQueuePacketsMutex);
	for (QueuedPacket* pQueuePacket : g_pQueuedPackets)
	{
		if (pQueuePacket->bIsConnectionless) {
			if (g_pNetworkThreadingModule.InDebug() == 1)
				Msg(PROJECT_NAME " - networkthreading: Processed %i bytes as connectionless! (%p)\n", pQueuePacket->pPacket.size, pQueuePacket);

			Util::server->ProcessConnectionlessPacket(&pQueuePacket->pPacket);
		} else {
			if (g_pNetworkThreadingModule.InDebug() == 1)
				Msg(PROJECT_NAME " - networkthreading: Processed %i bytes as net channel! (%p)\n", pQueuePacket->pPacket.size, pQueuePacket);

			CNetChan* netchan = func_NET_FindNetChannel(nSocket, pQueuePacket->pPacket.from);
			if (netchan)
				netchan->ProcessPacket(&pQueuePacket->pPacket, true);
		}

		delete pQueuePacket;
	}
	g_pQueuedPackets.clear();
}

static Detouring::Hook detour_CNetChan_Constructor;
static void hook_CNetChan_Constructor(CNetChan* pChannel)
{
	detour_CNetChan_Constructor.GetTrampoline<Symbols::CNetChan_Constructor>()(pChannel);

	auto it = g_pNetChannels.find(pChannel);
	if (it != g_pNetChannels.end())
		return;

	g_pNetChannels.insert(pChannel);
}


static Detouring::Hook detour_NET_RemoveNetChannel;
static void hook_NET_RemoveNetChannel(INetChannel* pChannel, bool bShouldRemove)
{
	detour_NET_RemoveNetChannel.GetTrampoline<Symbols::NET_RemoveNetChannel>()(pChannel, bShouldRemove);

	auto it = g_pNetChannels.find(pChannel);
	if (it == g_pNetChannels.end())
		return;

	g_pNetChannels.erase(it);
	// We don't need to do any cleanup since any packets that can't be passed to a channel since they have been removed are simply dropped.
}

void CNetworkThreadingModule::Think(bool bSimulating)
{
	CBaseServer* pServer = (CBaseServer*)Util::server;
	if (pServer)
		g_nChallengeNr.store(pServer->m_CurrentRandomNonce);

	// Sync ConVar values to atomics for network thread (avoids ConVar access in hot path)
	bool bQueryEnabled = networkthreading_queryresponse.GetBool();
	g_bQueryResponseEnabled.store(bQueryEnabled, std::memory_order_relaxed);
	g_flQueryResponseCacheTime.store(networkthreading_queryresponse_cachetime.GetFloat(), std::memory_order_relaxed);

	// Rebuild query response cache if needed (main thread for Lua hook)
	if (bQueryEnabled && g_bQueryResponseNeedsRebuild.load(std::memory_order_relaxed))
	{
		BuildQueryResponseCache();
	}
}

static ThreadHandle_t g_pNetworkThread = nullptr;
void CNetworkThreadingModule::ServerActivate(edict_t* pEdictList, int edictCount, int clientMax)
{
	CBaseServer* pServer = (CBaseServer*)Util::server;
	if (pServer)
		g_nChallengeNr.store(pServer->m_CurrentRandomNonce);

	// Sync ConVar values to atomics
	bool bQueryEnabled = networkthreading_queryresponse.GetBool();
	g_bQueryResponseEnabled.store(bQueryEnabled, std::memory_order_relaxed);
	g_flQueryResponseCacheTime.store(networkthreading_queryresponse_cachetime.GetFloat(), std::memory_order_relaxed);

	// Initialize query response cache
	if (bQueryEnabled)
	{
		InitQueryResponseInfo();
		BuildQueryResponseCache();
	}

	g_nThreadState.store(NetworkThreadState::STATE_RUNNING);
	if (g_pNetworkThread == nullptr)
	{
		ConDMsg(PROJECT_NAME " - networkthreading: Starting network thread...\n");
		g_pNetworkThread = CreateSimpleThread((ThreadFunc_t)NetworkThread, nullptr);
	}
}

void CNetworkThreadingModule::LevelShutdown()
{
	// Invalidate query response cache on map change
	g_bQueryResponseValid.store(false);
	g_bQueryResponseNeedsRebuild.store(true);

	if (g_pNetworkThread == nullptr)
		return;

	ConDMsg(PROJECT_NAME " - networkthreading: Stopping network thread...\n");
	if (g_nThreadState.load() != NetworkThreadState::STATE_NOTRUNNING)
	{
		g_nThreadState.store(NetworkThreadState::STATE_SHOULD_SHUTDOWN);
		while (g_nThreadState.load() != NetworkThreadState::STATE_NOTRUNNING) // Wait for shutdown
			ThreadSleep(0);
	}
	ReleaseThreadHandle(g_pNetworkThread);
	g_pNetworkThread = nullptr;
}

void CNetworkThreadingModule::InitDetour(bool bPreServer)
{
	if (bPreServer)
		return;

	SourceSDK::FactoryLoader engine_loader("engine");
	Detour::Create(
		&detour_NET_ProcessSocket, "NET_ProcessSocket",
		engine_loader.GetModule(), Symbols::NET_ProcessSocketSym,
		(void*)hook_NET_ProcessSocket, m_pID
	);

	Detour::Create(
		&detour_CNetChan_Constructor, "CNetChan_Constructor",
		engine_loader.GetModule(), Symbols::CNetChan_ConstructorSym,
		(void*)hook_CNetChan_Constructor, m_pID
	);

	Detour::Create(
		&detour_NET_RemoveNetChannel, "NET_RemoveNetChannel",
		engine_loader.GetModule(), Symbols::NET_RemoveNetChannelSym,
		(void*)hook_NET_RemoveNetChannel, m_pID
	);

	func_Filter_ShouldDiscard = (Symbols::Filter_ShouldDiscard)Detour::GetFunction(engine_loader.GetModule(), Symbols::Filter_ShouldDiscardSym);
	Detour::CheckFunction((void*)func_Filter_ShouldDiscard, "Filter_ShouldDiscard");

	func_Filter_SendBan = (Symbols::Filter_SendBan)Detour::GetFunction(engine_loader.GetModule(), Symbols::Filter_SendBanSym);
	Detour::CheckFunction((void*)func_Filter_SendBan, "Filter_SendBan");

	func_NET_GetPacket = (Symbols::NET_GetPacket)Detour::GetFunction(engine_loader.GetModule(), Symbols::NET_GetPacketSym);
	Detour::CheckFunction((void*)func_NET_GetPacket, "NET_GetPacket");

	func_NET_FindNetChannel = (Symbols::NET_FindNetChannel)Detour::GetFunction(engine_loader.GetModule(), Symbols::NET_FindNetChannelSym);
	Detour::CheckFunction((void*)func_NET_FindNetChannel, "NET_FindNetChannel");

	func_NET_SendPacket = (Symbols::NET_SendPacket)Detour::GetFunction(engine_loader.GetModule(), Symbols::NET_SendPacketSym);
	Detour::CheckFunction((void*)func_NET_SendPacket, "NET_SendPacket");

	// Command detours to make g_IPFilters threadsafe by applying a mutex
	Detour::Create(
		&detour_Filter_Add_f, "Filter_Add_f",
		engine_loader.GetModule(), Symbols::Filter_Add_fSym,
		(void*)hook_Filter_Add_f, m_pID
	);

	Detour::Create(
		&detour_removeip, "removeip",
		engine_loader.GetModule(), Symbols::removeipSym,
		(void*)hook_removeip, m_pID
	);

	Detour::Create(
		&detour_listip, "listip",
		engine_loader.GetModule(), Symbols::listipSym,
		(void*)hook_listip, m_pID
	);

	Detour::Create(
		&detour_writeip, "writeip",
		engine_loader.GetModule(), Symbols::writeipSym,
		(void*)hook_writeip, m_pID
	);
}