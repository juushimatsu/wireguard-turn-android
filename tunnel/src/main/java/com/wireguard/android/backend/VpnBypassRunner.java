/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.backend;

import android.util.Log;

import com.wireguard.util.NonNullForAll;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

import androidx.annotation.Nullable;

/**
 * Runs root shell commands to disguise the WireGuard VPN interface.
 *
 * <p>Strategy:
 * <ol>
 *   <li>Rename the tun interface (e.g. {@code wg0}) to the user-chosen name
 *       (e.g. {@code eth1}) using {@code ip link set … name …}.
 *       Many detection methods are name-heuristic-based.</li>
 *   <li>Delete the per-uid and fwmark routing rules that Android's
 *       ConnectivityService injects for VPN traffic.  These rules carry
 *       VPN semantics in the kernel and are visible via {@code ip rule} /
 *       {@code /proc/net/fib_rules}.</li>
 * </ol>
 *
 * <p>Limitation: the {@code NetworkCapabilities} object cached inside
 * ConnectivityService still carries {@code TRANSPORT_VPN}.  That object is
 * updated by the framework on route/rule changes, so after our rule removal
 * it will eventually lose the VPN transport on many devices.  The exact
 * behaviour depends on the OEM kernel + ConnectivityService version.
 *
 * <p>Requires {@code su} (Magisk / KernelSU / APatch) and {@code iproute2}.
 *
 * <p>This class lives in the {@code tunnel} module so it can be called
 * directly from {@link GoBackend} without a cross-module dependency.
 */
@NonNullForAll
public final class VpnBypassRunner {

    private static final String TAG = "WireGuard/VpnBypass";

    /** Linux interface name max length. */
    private static final int IFNAME_MAX = 15;

    private VpnBypassRunner() { }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Apply VPN bypass: rename {@code originalName} → {@code targetName} and
     * strip Android's VPN routing rules.
     *
     * @param originalName Interface name currently used by wireguard-go
     *                     (equals the tunnel name passed to {@code wgTurnOn}).
     * @param targetName   Desired disguise name supplied by the user.
     * @return {@code true} if all mandatory commands succeeded.
     */
    public static boolean apply(final String originalName, final String targetName) {
        final String clean = sanitize(targetName);
        if (clean.isEmpty()) {
            Log.w(TAG, "apply: sanitized targetName is empty, aborting");
            return false;
        }
        Log.i(TAG, "Applying VPN bypass: " + originalName + " -> " + clean);

        // Build the shell script.
        // Commands that are "best-effort" (cleanup of existing rules that may
        // not exist) end with "|| true" so the script continues on failure.
        final String script =
                // Bring down before rename to avoid EBUSY
                "ip link set " + originalName + " down && " +
                // Rename
                "ip link set " + originalName + " name " + clean + " && " +
                // Bring back up
                "ip link set " + clean + " up && " +
                // Remove Android uid-range VPN routing rules (IPv4)
                "ip rule del iif " + originalName + " 2>/dev/null || true && " +
                "ip rule del oif " + originalName + " 2>/dev/null || true && " +
                // Remove fwmark-based VPN rules (0x20000 = MARK_VPN in AOSP net code)
                "ip rule del fwmark 0x20000/0x20000 2>/dev/null || true && " +
                // Same for IPv6
                "ip -6 rule del iif " + originalName + " 2>/dev/null || true && " +
                "ip -6 rule del oif " + originalName + " 2>/dev/null || true && " +
                "ip -6 rule del fwmark 0x20000/0x20000 2>/dev/null || true" +
                // Cache
                "ip route flush cache 2>/dev/null || true && " +
                "ip -6 route flush cache 2>/dev/null || true && ";

        return runAsRoot(script);
    }

    /**
     * Revert bypass: rename {@code currentName} back to {@code originalName}.
     * Normally not needed — just tear the VPN down — but exposed for testing.
     */
    public static boolean revert(final String currentName, final String originalName) {
        if (currentName.isEmpty() || originalName.isEmpty()) return false;
        Log.i(TAG, "Reverting VPN bypass: " + currentName + " -> " + originalName);
        final String script =
                "ip link set " + currentName + " down && " +
                "ip link set " + currentName + " name " + originalName + " && " +
                "ip link set " + originalName + " up";
        return runAsRoot(script);
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Run a shell script via {@code su -c '…'}.
     *
     * <p>We intentionally do NOT use the shared {@link com.wireguard.android.util.RootShell}
     * because that helper is constructed in the UI module and injected only into
     * {@link WgQuickBackend}.  {@link GoBackend} does not hold a reference to it.
     * A direct {@code Runtime.exec()} call keeps the tunnel module self-contained.
     */
    private static boolean runAsRoot(final String script) {
        try {
            final Process process = Runtime.getRuntime().exec(new String[]{"su", "-c", script});
            final int exit = process.waitFor();
            if (exit != 0) {
                final BufferedReader err = new BufferedReader(
                        new InputStreamReader(process.getErrorStream()));
                final StringBuilder sb = new StringBuilder();
                String line;
                while ((line = err.readLine()) != null) sb.append(line).append('\n');
                Log.e(TAG, "Root script exited " + exit + ": " + sb);
            }
            return exit == 0;
        } catch (final Exception e) {
            Log.e(TAG, "Failed to execute root script", e);
            return false;
        }
    }

    /**
     * Strip characters that are illegal in Linux interface names and truncate
     * to {@value #IFNAME_MAX} characters.  Returns an empty string if nothing
     * valid remains (caller should abort or use a fallback).
     */
    public static String sanitize(final String name) {
        if (name == null) return "";
        final StringBuilder sb = new StringBuilder(IFNAME_MAX);
        for (final char c : name.toCharArray()) {
            if (Character.isLetterOrDigit(c) || c == '-' || c == '_' || c == '.') {
                sb.append(c);
                if (sb.length() == IFNAME_MAX) break;
            }
        }
        return sb.toString();
    }
}
