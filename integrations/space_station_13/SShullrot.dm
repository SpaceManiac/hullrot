// Used to manage the Hullrot process.

/datum/config_entry/string/hullrot_control_addr
	protection = CONFIG_ENTRY_LOCKED | CONFIG_ENTRY_HIDDEN
	config_entry_value = "127.0.0.1:10961"

SUBSYSTEM_DEF(hullrot)
	name = "Hullrot"
	priority = 25
	flags = SS_BACKGROUND
	wait = 2
	init_order = -50  // Very late initialize

	var/const/dll_major = 0  // Major version must be exactly this
	var/const/dll_minor = 1  // Minor version must be at least this
	var/loaded_version  // For VV inspection
	var/server_version
	var/dead_because

	var/currently_playing = -1
	var/checked_events = FALSE
	var/subspace_ticker = 0
	var/subspace_groups

	var/obj/effect/statclick/hullrot_auth/auth_statclick

// ----------------------------------------------------------------------------
// Initialization

/datum/controller/subsystem/hullrot/Initialize()
	auth_statclick = new(null, "Connect to Hullrot and then click here to authenticate")
	dll_connect()
	return ..()

/datum/controller/subsystem/hullrot/proc/lib()
	return world.system_type == MS_WINDOWS ? "hullrot.dll" : "libhullrot.so"

/datum/controller/subsystem/hullrot/proc/dll_connect()
	// Load the DLL and check the version
	var/list/version = get_dll_version()
	if (version == null)
		return abort("[name] could not be loaded and has been disabled.")
	if (version["error"])
		return abort("[name] version check failed: [version["error"]].")
	if (version["major"] != dll_major || version["minor"] < dll_minor)
		return abort("[name] [dll_major].[dll_minor] was expected, but incompatible [version["version"]] was supplied.")
	loaded_version = version["version"]

	var/list/res = json_decode(call(lib(), "hullrot_init")(CONFIG_GET(string/hullrot_control_addr)))
	var/error = res["error"] || res["Fatal"] || res["Debug"]
	if (error || !res["Version"])
		return abort("[name] failed to initialize: [error]")
	server_version = res["Version"]["version"]
	dead_because = null
	log_world("[name] active: dll [loaded_version], server [server_version]")

	for (var/client/C in GLOB.clients)
		check_connected(C)
	for (var/mob/living/L in GLOB.player_list)
		L.hullrot_reset()

/datum/controller/subsystem/hullrot/proc/get_dll_version()
	// In its own proc so if it crashes, dll_initialize can check for null.
	return json_decode(call(lib(), "hullrot_dll_version")())

/datum/controller/subsystem/hullrot/stat_entry(msg)
	..(dead_because || "C:[loaded_version] S:[server_version]")

// ----------------------------------------------------------------------------
// Shutdown

/datum/controller/subsystem/hullrot/Shutdown()
	if (loaded_version)
		loaded_version = null
		call(lib(), "hullrot_stop")()

// because the DLL starts a thread, we have to make *extra* sure to join it
/world/Del()
	if (SShullrot && SShullrot.loaded_version && SShullrot.can_fire)
		SShullrot.Shutdown()
		sleep(10)
	..()

// ----------------------------------------------------------------------------
// Error handling

/datum/controller/subsystem/hullrot/proc/abort(msg)
	dead_because = msg
	log_world(msg)
	message_admins("(<a href='?src=[REF(src)];[HrefToken(TRUE)];restart=1'>restart</a>) [msg]")
	can_fire = FALSE

	var/list/images = list()
	for (var/mob/living/L in GLOB.player_list)
		images += L.hullrot_bubble
	for (var/mob/living/L in GLOB.player_list)
		if (L.client)
			L.client.images -= images

/datum/controller/subsystem/hullrot/proc/warn(msg)
	message_admins("[name] warning: [msg]")

/datum/controller/subsystem/hullrot/proc/restart()
	message_admins("Admin [key_name_admin(usr)] is restarting [name].")
	Shutdown()
	can_fire = TRUE
	currently_playing = initial(currently_playing)  // force a resend
	dll_connect(TRUE)

/datum/controller/subsystem/hullrot/vv_get_dropdown()
	. = ..()
	. += "---"
	.["Restart"] = "?src=[REF(src)];[HrefToken()];restart=1"

/datum/controller/subsystem/hullrot/Topic(href, href_list)
	if(..() || !check_rights(R_ADMIN, FALSE) || !usr.client.holder.CheckAdminHref(href, href_list))
		return

	if(href_list["restart"])
		restart()

// ----------------------------------------------------------------------------
// General processing

/datum/controller/subsystem/hullrot/proc/control(what, data)
	if (!loaded_version || !can_fire)
		return

	// Send the control command if specified, or just read events.
	checked_events = TRUE
	var/events
	if (what)
		events = json_decode(call(lib(), "hullrot_control")(json_encode(list("[what]" = data))))
	else
		events = json_decode(call(lib(), "hullrot_control")())

	// Handle the read events.
	for (var/event in events)
		if ((data = event["Fatal"]))
			abort("Hullrot has crashed: [data]")

		else if ((data = event["Debug"]))
			warn(data)

		else if ((data = event["Refresh"]))
			var/client/C = GLOB.directory[data]
			if (istype(C))
				C.hullrot_authed = TRUE  // they're authenticated
			var/mob/living/L = C && C.mob
			if (istype(L))
				L.hullrot_reset()

		else if ((data = event["Hear"]))
			var/client/C = GLOB.directory[data["speaker"]]
			var/mob/living/speaker = C && C.mob
			C = GLOB.directory[data["hearer"]]
			var/mob/living/hearer = C && C.mob
			if (!istype(speaker) || !istype(hearer))
				continue

			// Issue forth the textual notification...
			var/atom/movable/abstract_speaker = speaker
			if (data["freq"])
				abstract_speaker = new /atom/movable/virtualspeaker(null, speaker)
			to_chat(hearer, hearer.hullrot_compose(abstract_speaker, text2path(data["language"]), data["freq"]))

		else if ((data = event["HearSelf"]))
			var/client/C = GLOB.directory[data["who"]]
			var/mob/living/speaker = C && C.mob
			if (!istype(speaker))
				continue

			if (!speaker.can_hear())
				if (!data["freq"])
					to_chat(speaker, "<span class='notice'>You can't hear yourself!</span>")
			else if (data["freq"])
				var/atom/movable/virtualspeaker/virt = new(null, speaker)
				to_chat(speaker, speaker.hullrot_compose(virt, text2path(data["language"]), data["freq"]))

		else if ((data = event["CannotSpeak"]))
			var/client/C = GLOB.directory[data]
			var/mob/living/speaker = C && C.mob
			if (!istype(speaker))
				continue

			to_chat(speaker, "<span class='warning'>You find yourself unable to speak!</span>")

		else if ((data = event["SpeechBubble"]))
			var/client/C = GLOB.directory[data["who"]]
			var/mob/living/speaker = C && C.mob
			if (!istype(speaker))
				continue

			var/image/bubble = speaker.hullrot_bubble
			if (!bubble)
				speaker.hullrot_bubble = bubble = image('icons/mob/talk.dmi', speaker.hullrot_audio_source(), "[speaker.bubble_icon]0", FLY_LAYER - 0.01)
			else
				bubble.icon_state = "[speaker.bubble_icon]0"
				bubble.loc = speaker.hullrot_audio_source()

			for (var/mob/living/L in GLOB.player_list)
				if (!L.client)
					continue
				if (L.ckey in data["with"])
					L.client.images |= bubble
				else
					L.client.images -= bubble

		else if ((data = event["NeedsRegistration"]))
			var/name = data["untrusted_username"]
			var/client/C = GLOB.directory[ckey(name)]
			if(C)
				INVOKE_ASYNC(C, /client.proc/hullrot_auth_prompt, "[name] connected to Hullrot. If this is you, provide the code:")

		else if ((data = event["BadRegistration"]))
			var/client/C = GLOB.directory[data["ckey"]]
			if(C)
				INVOKE_ASYNC(C, /client.proc/hullrot_auth_prompt, "That code does not appear to be valid. Try again:")

		else if ((data = event["IsConnected"]))
			var/client/C = GLOB.directory[data["ckey"]]
			if(C)
				C.hullrot_authed = data["connected"]

/datum/controller/subsystem/hullrot/fire()
	checked_events = FALSE

	var/new_playing = SSticker.IsRoundInProgress()
	if (new_playing != currently_playing)
		control("Playing", new_playing)
		currently_playing = new_playing

	if (subspace_ticker >= 0)
		subspace_ticker += wait
		if (subspace_ticker >= 50 || !subspace_groups)
			subspace_ticker = -1
			INVOKE_ASYNC(src, .proc/subspace_update)

	for (var/mob/living/L in GLOB.player_list)
		if (L.client && (L.hullrot_needs_update || prob(5)))
			L.hullrot_update()

	if (!checked_events)
		control()

/datum/controller/subsystem/hullrot/proc/subspace_update()
	var/groups = list()
	var/group = 1

	for(var/z in 1 to world.maxz)
		if ("[z]" in groups)
			continue
		var/datum/signal/subspace/signal = new(list("message" = "TEST"))
		signal.frequency = FREQ_COMMON
		signal.server_type = /obj/machinery/telecomms/broadcaster
		signal.levels = list(z)
		signal.send_to_receivers()
		if (signal.data["done"])
			for(var/level in signal.levels)
				groups["[level]"] = group
			group += 1

	if (list2params(subspace_groups) != list2params(groups))
		subspace_groups = groups
		control("Linkage", groups)
		for (var/mob/living/L in GLOB.player_list)
			L.hullrot_update()
	subspace_ticker = 0

// ----------------------------------------------------------------------------
// Controls

/datum/controller/subsystem/hullrot/proc/patch_mob_state(client/C, list/patch)
	patch["ckey"] = C.ckey
	control("PatchMobState", patch)

/datum/controller/subsystem/hullrot/proc/set_ptt(client/C, freq)
	control("SetPTT", list("who" = C.ckey, "freq" = (freq && text2num(freq))))

/datum/controller/subsystem/hullrot/proc/set_ghost(client/C)
	control("SetGhost", C.ckey)

/datum/controller/subsystem/hullrot/proc/register(client/C, code)
	control("Register", list("cert_hash" = code, "ckey" = C.ckey))

/datum/controller/subsystem/hullrot/proc/check_connected(client/C)
	control("CheckConnected", list("ckey" = C.ckey))
