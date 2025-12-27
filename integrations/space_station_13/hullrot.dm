// ----------------------------------------------------------------------------
// Push-to-talk stat panel and key handling

#define HULLROT_STAT_HEADER "— Radio ————————————————"

/mob/living
	var/list/hullrot_stats
	var/hullrot_ptt
	var/hullrot_cache
	var/image/hullrot_bubble
	var/hullrot_needs_update = FALSE

/mob/living/get_status_tab_items()
	. = ..()
	if (client && SShullrot.initialized && SShullrot.can_fire && hullrot_radio_allowed())
		var/list/keys_used = list()

		if (!client.hullrot_authed)
			. += HULLROT_STAT_HEADER
			. += list(list("Authenticate: ", SShullrot.auth_statclick.name, "src=\ref[SShullrot.auth_statclick];statpanel_item_click=left"))
			. += ""
			return
		else if (!hullrot_radio_allowed())
			return

		. += HULLROT_STAT_HEADER
		var/turf/T = get_turf(src)
		for (var/obj/item/radio/R in view(1, src))
			if (!istype(R, /obj/item/radio/intercom) && !(R in src))
				continue  // can't talk into a non-intercom you're not holding
			if (!R.is_on() || R.wires.is_cut(WIRE_TX) || (istype(R, /obj/item/radio/headset) && !R.get_broadcasting()))
				. += "\the [R] (off)"
				continue  // can't talk into a disabled radio
			if (R.subspace_transmission && (!SShullrot.subspace_groups || !SShullrot.subspace_groups["[T.z]"]))
				. += "\the [R] (not responding)"
				continue  // can't talk into headsets while comms are down

			. += "\the [R]"
			hullrot_stat(., keys_used, R, "Tuner", R.get_frequency())
			for (var/channel in R.channels)
				if (R.channels[channel])
					hullrot_stat(., keys_used, R, channel, GLOB.default_radio_channels[channel])

		hullrot_stats &= keys_used
		if (keys_used.len)
			if (!(hullrot_ptt in keys_used))
				hullrot_ptt = keys_used[1]
				var/obj/S = hullrot_stats[hullrot_ptt]
				S.name = "Active - hold V to talk"
		else
			hullrot_ptt = null

		if (client.keys_held["V"])
			ptt_tick()

		. += ""

/mob/living/proc/ptt_tick()
	var/ptt_freq
	if (hullrot_radio_allowed() && !(incapacitated & ~INCAPABLE_GRAB))
		var/obj/effect/statclick/radio/current = hullrot_ptt && hullrot_stats[hullrot_ptt]
		ptt_freq = current && current.freq

	if (hullrot_cache["ptt_freq"] != ptt_freq)
		hullrot_cache["ptt_freq"] = ptt_freq
		SShullrot.set_ptt(client, ptt_freq)

/mob/living/proc/hullrot_stat(output, keys_used, radio, channel, frequency)
	var/key = "[REF(radio)]:[channel]"
	if (hullrot_ptt == null)
		hullrot_ptt = key
	keys_used += key

	var/obj/effect/statclick/radio/O = hullrot_stats[key]
	if (!O)
		hullrot_stats[key] = O = new /obj/effect/statclick/radio(null, "Available", src)
		O.key = key
	O.freq = frequency
	O.name = (hullrot_ptt == key) ? "Active - hold V to talk" : "Available"
	output += list(list("• [channel]: ", O.name, "src=\ref[O];statpanel_item_click=left"))

/obj/effect/statclick/radio
	var/key
	var/freq

/obj/effect/statclick/radio/Click()
	var/mob/living/M = usr
	M.hullrot_ptt = key
	if (M.client.keys_held["V"])
		M.ptt_tick()

/mob/living/key_down(_key, client/user)
	switch(_key)
		if("V")
			ptt_tick()
			hullrot_update()
		else
			return ..()

/mob/living/key_up(_key, client/user)
	switch(_key)
		if("V")
			if (hullrot_cache["ptt_freq"] != null)
				hullrot_cache["ptt_freq"] = null
				SShullrot.set_ptt(user, null)
				hullrot_update()
		else
			return ..()

// ----------------------------------------------------------------------------
// Authentication stat panel

/client
	var/hullrot_authed = FALSE

/client/New()
	. = ..()
	SShullrot.check_connected(src)

/obj/effect/statclick/hullrot_auth

/obj/effect/statclick/hullrot_auth/Click()
	if (usr.client)
		usr.client.hullrot_auth_prompt()

/client/proc/hullrot_auth_prompt(message = "Provide authentication code:")
	var/code = input(src, message, "Hullrot Authentication") as text|null
	if (code)
		SShullrot.register(src, code)

// ----------------------------------------------------------------------------
// Admin ghost stat panel

/obj/effect/statclick/dead_radio
	var/enabled = FALSE

/obj/effect/statclick/dead_radio/Click()
	var/mob/dead/M = usr
	enabled = !enabled
	name = "[enabled ? "Enabled" : "Disabled"] (click to toggle)"
	if (M.client && check_rights_for(M.client, R_ADMIN))
		SShullrot.patch_mob_state(M.client, list("ghost_ears" = enabled))

/client
	var/obj/effect/statclick/dead_radio/hullrot_hear_all

/mob/dead/get_status_tab_items()
	. = ..()
	if (client && SShullrot.initialized && SShullrot.can_fire)
		if (!client.hullrot_authed)
			. += HULLROT_STAT_HEADER
			. += list(list("Authenticate: ", SShullrot.auth_statclick.name, "src=\ref[SShullrot.auth_statclick];statpanel_item_click=left"))
			. += ""
		else if (check_rights_for(client, R_ADMIN))
			if (!client.hullrot_hear_all)
				client.hullrot_hear_all = new(null, "Disabled (click to toggle)")
			. += HULLROT_STAT_HEADER
			. += list(list("Ghost ears: ", client.hullrot_hear_all.name, "src=\ref[client.hullrot_hear_all];statpanel_item_click=left"))
			. += ""

// ----------------------------------------------------------------------------
// Location-based can-hear and can-speak checks

/mob/living/proc/hullrot_update()
	hullrot_needs_update = FALSE
	if (!SShullrot.can_fire || !client)
		return

	var/list/patch = hullrot_make_patch(hullrot_cache)
	if (patch.len)
		SShullrot.patch_mob_state(client, patch)

/mob/living/proc/hullrot_make_patch(list/cache)
	. = list()

	// Permissions
	var/admin = check_rights_for(client, R_ADMIN)
	if (cache["admin"] != admin)
		cache["admin"] = admin
		.["is_admin"] = admin

	// Mob-level speaking and hearing
	var/can_speak = (can_speak() && (stat == CONSCIOUS || stat == SOFT_CRIT)) || FALSE
	var/can_hear = (can_hear() && (stat == CONSCIOUS || stat == SOFT_CRIT)) || FALSE
	if (cache["can_speak"] != can_speak)
		cache["can_speak"] = can_speak
		.["mute"] = !can_speak
	if (cache["can_hear"] != can_hear)
		cache["can_hear"] = can_hear
		.["deaf"] = !can_hear
	if (!can_speak && !can_hear)
		return

	// Languages
	var/datum/language_holder/langs = get_language_holder()
	var/list/language_names = list()
	for (var/L in langs.understood_languages)
		language_names += "[L]"
	var/stringified = list2params(language_names)
	if (cache["lang_known"] != stringified)
		cache["lang_known"] = stringified
		.["known_languages"] = language_names

	var/datum/language/default_lang = langs.get_selected_language()
	var/default_name = "[default_lang]"
	if (cache["lang_speaking"] != default_name)
		cache["lang_speaking"] = default_name
		.["current_language"] = default_name

	// Position
	var/turf/T = get_turf(src)
	if (cache["z"] != T.z)
		cache["z"] = T.z
		.["z"] = T.z

	// Local hearers
	var/speak_range = (client.keys_held["V"] || stat == SOFT_CRIT) ? 1 : 7
	var/audio_source = hullrot_audio_source()
	var/hearers = get_hearers_in_view(7, audio_source)
	if (can_speak)
		var/list/local_with = list()
		for (var/mob/L in hearers)
			if (L.client && L != src && get_dist(audio_source, L) <= speak_range)
				local_with += L.ckey
		for (var/obj/machinery/holopad/H in hearers)
			if (get_dist(audio_source, H) <= speak_range)
				for (var/mob/living/L in H.masters)
					if (L.client && L != src)
						local_with += L.ckey

		var/new_local = list2params(local_with)
		if (cache["local_with"] != new_local)
			// make sure that we propagate changes to others as well
			var/previous = params2list(cache["local_with"])
			for(var/other_ckey in (previous ^ local_with))
				var/client/C = GLOB.directory[other_ckey]
				var/mob/living/speaker = C && C.mob
				if (istype(speaker))
					speaker.hullrot_needs_update = TRUE

			cache["local_with"] = new_local
			.["local_with"] = local_with

	// Certain mobs can speak locally but not over the radio
	if (!hullrot_radio_allowed())
		can_speak = FALSE

	// Hot and heard radio frequencies
	var/list/hot_freqs = list()
	var/list/hear_freqs = list()
	for(var/obj/item/radio/R in (hearers | src.contents))
		if (get_dist(audio_source, R) > R.canhear_range || !R.is_on())
			continue
		if (R.subspace_transmission && (!SShullrot.subspace_groups || !SShullrot.subspace_groups["[T.z]"]))
			continue

		if (can_speak && (R.get_broadcasting() && !istype(R, /obj/item/radio/headset)) && (!R.wires || !R.wires.is_cut(WIRE_TX)) && get_dist(audio_source, R) <= speak_range)
			hot_freqs |= R.get_frequency()

		if (can_hear && R.get_listening() && (!R.wires || !R.wires.is_cut(WIRE_RX)) && R.can_receive(R.get_frequency(), list(T.z)))
			hear_freqs |= R.get_frequency()
			for (var/channel in R.channels)
				if (R.channels[channel])
					hear_freqs |= GLOB.default_radio_channels[channel]

	var/new_hot = list2params(hot_freqs)
	var/new_hear = list2params(hear_freqs)
	if (cache["hot"] != new_hot)
		cache["hot"] = new_hot
		.["hot_freqs"] = hot_freqs
	if (cache["hear"] != new_hear)
		cache["hear"] = new_hear
		.["hear_freqs"] = hear_freqs

/mob/living/proc/hullrot_reset()
	hullrot_stats = list()
	hullrot_cache = list()
	hullrot_update()

/mob/living/Login()
	..()
	hullrot_reset()

/mob/living/Move()
	. = ..()
	if(. && client)
		hullrot_needs_update = TRUE

// Radios must always be hearing sensitive because we cheat by looking for "hearers" to find what radios a mob can hear.
/obj/item/radio/Initialize()
	. = ..()
	if (!istype(src, /obj/item/radio/headset))
		become_hearing_sensitive("hullrot")

/obj/item/radio/equipped(mob/living/user, slot)
	..()
	if (isliving(user) && user.client)
		user.hullrot_update()

/obj/item/radio/dropped(mob/living/user)
	..()
	if (isliving(user) && user.client)
		user.hullrot_update()

/obj/proc/hullrot_check_all_hearers(range = 7)
	for (var/mob/living/M in get_hearers_in_view(range, src))
		M.hullrot_needs_update = TRUE

/obj/item/radio/Initialize()
	. = ..()
	hullrot_check_all_hearers(canhear_range)

/obj/item/radio/ui_act(action, params, datum/tgui/ui)
	. = ..()
	if (action in list("frequency", "listen", "broadcast", "channel", "subspace"))
		hullrot_check_all_hearers(canhear_range)

/obj/item/radio/emp_act()
	. = ..()
	hullrot_check_all_hearers(canhear_range)
	addtimer(CALLBACK(src, .proc/hullrot_check_all_hearers, canhear_range), 201)  // un-EMP delay + 1

/mob/living/afterShuttleMove()
	. = ..()
	if (. && client)
		hullrot_needs_update = TRUE

/mob/living/carbon/human/update_stat()
	var/previous = stat
	. = ..()
	if (client && stat != previous)
		hullrot_update()

/mob/dead/Login()
	. = ..()
	SShullrot.set_ghost(client)

/obj/machinery/door/open()
	. = ..()
	if(.)
		hullrot_check_all_hearers()

/obj/machinery/door/close()
	. = ..()
	if(.)
		hullrot_check_all_hearers()

// ----------------------------------------------------------------------------
// AI restriction and holopad handling

/mob/living/proc/hullrot_radio_allowed()
	return TRUE

/mob/living/silicon/ai/hullrot_radio_allowed()
	return FALSE

/mob/living/silicon/robot/hullrot_radio_allowed()
	return mainframe == null

/mob/living/proc/hullrot_audio_source()
	var/mob/eye/camera/remote/holo/holoEye = remote_control
	if (istype(holoEye))
		var/origin = holoEye.origin_ref?.resolve()
		if (origin)
			return origin
	return src

/mob/living/silicon/ai/hullrot_audio_source()
	var/obj/machinery/holopad/T = current
	if (istype(T) && T.masters[src])
		return T
	if (istype(loc, /obj/item/aicard))
		return loc
	return src

// ----------------------------------------------------------------------------
// Message composition

/mob/living/proc/hullrot_compose(atom/movable/speaker, datum/language/message_language, radio_freq, list/spans, message_mode)
	// Intended to mimic compose_mesage() from saycode
	var/spanpart1 = "<span class='[radio_freq ? get_radio_span(radio_freq) : "game say"]'>"
	var/spanpart2 = "<span class='name'>"
	// Use allinone as a way to get the channel name. Not yet compatible with customizing channel names at telecomms.
	var/freqpart = radio_freq ? "\[[get_radio_name(radio_freq, /obj/machinery/telecomms/allinone::frequency_infos["[radio_freq]"]["name"])]\] " : ""
	var/namepart = speaker.get_message_voice()
	var/endspanpart = "</span>"

	//Message
	var/datum/language/D = GLOB.language_datum_instances[message_language]
	var/verbpart = speaker.verb_say
	if (verbpart == "says")
		verbpart = "speaks"

	var/langpart = ""
	if(!has_language(message_language))
		langpart = " in an unknown language"

	var/messagepart = " <span class='message'>[verbpart][langpart].</span></span>"

	var/languageicon = ""
	if(istype(D) && D.display_icon(src))
		languageicon = "[D.get_icon()] "

	return "[spanpart1][spanpart2][freqpart][languageicon][compose_track_href(speaker, namepart)][namepart][compose_job(speaker, message_language, null, radio_freq)][endspanpart][messagepart]"

#undef HULLROT_STAT_HEADER
