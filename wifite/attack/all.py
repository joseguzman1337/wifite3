#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .wep import AttackWEP
from .wpa import AttackWPA
from .wps import AttackWPS
from .pmkid import AttackPMKID
from ..config import Configuration
from ..util.color import Color


class AttackAll(object):

    @classmethod
    def attack_multiple(cls, targets, realtime_crack_manager=None):
        """
        Attacks all given `targets` (list[wifite.model.target]) until user interruption.
        Returns: Number of targets that were attacked (int)
        """
        if any(t.wps for t in targets) and not AttackWPS.can_attack_wps():
            # Warn that WPS attacks are not available.
            Color.pl(
                "{!} {O}Note: WPS attacks are not possible because you do not have {C}reaver{O} nor {C}bully{W}"
            )

        attacked_targets = 0
        targets_remaining = len(targets)
        for index, target in enumerate(targets, start=1):
            # Before processing each new target, update real-time status if manager exists
            # This allows passwords found for *other* targets to be reported even if current target selection is manual.
            if realtime_crack_manager:
                realtime_crack_manager.update_status()

            attacked_targets += 1
            targets_remaining -= 1

            # Check if this target was already cracked by the real-time manager
            if (
                realtime_crack_manager
                and realtime_crack_manager.get_cracked_password(target.bssid)
            ):
                Color.pl(
                    "\n{+} Target {C}%s{W} ({C}%s{W}) already cracked by real-time manager. Password: {G}%s{W}"
                    % (
                        target.bssid,
                        (
                            target.essid
                            if target.essid_known
                            else "{O}ESSID unknown{W}"
                        ),
                        realtime_crack_manager.get_cracked_password(
                            target.bssid
                        ),
                    )
                )
                if realtime_crack_manager.is_actively_cracking(
                    target.bssid
                ):  # Should have been stopped when password found
                    realtime_crack_manager.stop_current_crack_attempt()
                continue  # Move to the next target in the list

            bssid = target.bssid
            essid = (
                target.essid if target.essid_known else "{O}ESSID unknown{W}"
            )

            Color.pl(
                "\n{+} ({G}%d{W}/{G}%d{W})" % (index, len(targets))
                + " Starting attacks against {C}%s{W} ({C}%s{W})"
                % (bssid, essid)
            )

            should_continue = cls.attack_single(
                target, targets_remaining, realtime_crack_manager
            )
            if not should_continue:
                break

        # Final status update for any lingering sessions after all targets are processed
        if realtime_crack_manager:
            Color.pl(
                "{+} Performing final real-time cracker status update..."
            )
            realtime_crack_manager.update_status()  # Check for any last-minute cracks
            if (
                realtime_crack_manager.is_actively_cracking()
            ):  # If any session is still running (e.g. for a target not in loop)
                realtime_crack_manager.stop_current_crack_attempt(
                    cleanup_hash_file=True
                )

        return attacked_targets

    @classmethod
    def attack_single(
        cls, target, targets_remaining, realtime_crack_manager=None
    ):
        """
        Attacks a single `target` (wifite.model.target).
        Returns: True if attacks should continue, False otherwise.
        """

        attacks = []

        if Configuration.use_eviltwin:
            # TODO: EvilTwin attack
            pass

        elif "WEP" in target.encryption:
            attacks.append(AttackWEP(target))

        elif (
            "WPA" in target.encryption
        ):  # Also handles WPA2, WPA3 due to Target.encryption logic
            # WPA can have multiple attack vectors:

            # WPS (Generally not applicable to WPA3-only, but APs can be mixed mode)
            if (
                not Configuration.use_pmkid_only and not target.is_wpa3
            ):  # WPS is not part of WPA3-SAE
                if (
                    target.wps != False and AttackWPS.can_attack_wps()
                ):  # target.wps should be WPSState.NONE or actual state
                    # Pixie-Dust
                    if Configuration.wps_pixie:
                        attacks.append(AttackWPS(target, pixie_dust=True))
                    # PIN attack
                    if Configuration.wps_pin:
                        attacks.append(AttackWPS(target, pixie_dust=False))

            if (
                not Configuration.wps_only
            ):  # Allow PMKID and Handshake if not wps_only
                # PMKID (Applicable to WPA/WPA2/WPA3)
                # Pass realtime_crack_manager to AttackPMKID constructor
                attacks.append(AttackPMKID(target, realtime_crack_manager))

                # Handshake capture (Skipped internally by AttackWPA for WPA3)
                if not Configuration.use_pmkid_only:
                    # Pass realtime_crack_manager to AttackWPA constructor
                    attacks.append(AttackWPA(target, realtime_crack_manager))

        if len(attacks) == 0:
            Color.pl(
                "{!} {R}Error: {O}Unable to attack {C}%s{O}: no attacks available or applicable for its configuration.{W}"
                % target.bssid
            )
            return True  # Keep attacking other targets (skip)

        while len(attacks) > 0:
            # Before running next queued attack, check real-time status
            if realtime_crack_manager:
                cracked_info = realtime_crack_manager.update_status()
                if cracked_info:
                    cracked_bssid, cracked_password = cracked_info
                    if cracked_bssid == target.bssid:
                        Color.pl(
                            f"{{G}}Real-time cracker found password for current target {target.bssid}. Stopping other attacks on this target.{W}"
                        )
                        # The password saving and session stop is handled by RealtimeCrackManager
                        return True  # Successfully "attacked", move to next target

            attack = attacks.pop(0)
            try:
                result = (
                    attack.run()
                )  # Attack's run() method might now use realtime_crack_manager
                if result:
                    # If a standard attack succeeded, stop any real-time cracking for this target
                    if (
                        realtime_crack_manager
                        and realtime_crack_manager.is_actively_cracking(
                            target.bssid
                        )
                    ):
                        Color.pl(
                            f"{{G}}Stopping real-time cracking for {target.bssid} as {attack.__class__.__name__} succeeded.{W}"
                        )
                        realtime_crack_manager.stop_current_crack_attempt(
                            cleanup_hash_file=False
                        )
                    break  # Attack was successful, stop other attacks on this target.
            except Exception as e:
                Color.pexception(e)
                continue
            except KeyboardInterrupt:
                Color.pl("\n{!} {O}Interrupted{W}\n")
                answer = cls.user_wants_to_continue(
                    targets_remaining, len(attacks)
                )
                if answer is True:
                    continue  # Keep attacking the same target (continue)
                elif answer is None:
                    return True  # Keep attacking other targets (skip)
                else:
                    return False  # Stop all attacks (exit)

        if attack.success:
            attack.crack_result.save()

        return True  # Keep attacking other targets

    @classmethod
    def user_wants_to_continue(cls, targets_remaining, attacks_remaining=0):
        """
        Asks user if attacks should continue onto other targets
        Returns:
            True if user wants to continue, False otherwise.
        """
        if attacks_remaining == 0 and targets_remaining == 0:
            return  # No targets or attacksleft, drop out

        prompt_list = []
        if attacks_remaining > 0:
            prompt_list.append(
                Color.s("{C}%d{W} attack(s)" % attacks_remaining)
            )
        if targets_remaining > 0:
            prompt_list.append(
                Color.s("{C}%d{W} target(s)" % targets_remaining)
            )
        prompt = " and ".join(prompt_list) + " remain"
        Color.pl("{+} %s" % prompt)

        prompt = "{+} Do you want to"
        options = "("

        if attacks_remaining > 0:
            prompt += " {G}continue{W} attacking,"
            options += "{G}C{W}{D}, {W}"

        if targets_remaining > 0:
            prompt += " {O}skip{W} to the next target,"
            options += "{O}s{W}{D}, {W}"

        options += "{R}e{W})"
        prompt += " or {R}exit{W} %s? {C}" % options

        from ..util.input import raw_input

        answer = raw_input(Color.s(prompt)).lower()

        if answer.startswith("s"):
            return None  # Skip
        elif answer.startswith("e"):
            return False  # Exit
        else:
            return True  # Continue
