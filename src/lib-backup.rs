//! SMB1 autosplitter for Mesen2RTA (native Linux).
//!
//! Settings (visible in LiveSplit One's autosplitter panel):
//!   • title_screen_delay — ON : timer starts when the emulator resets
//!     (detected by the frame counter dropping back to ≤ 3).
//!     This is the classic "title-screen delay" timing used in SMB1 any%.
//!   • title_screen_delay — OFF: timer starts when the game engine reaches
//!     sub-state 8 (original "no delay" behaviour).
//!
//! To enable title_screen_delay you must first find the frame-counter
//! pointer chain — see the instructions above FC_CHAIN_READY below.

#![no_std]

use asr::{
    future::{next_tick, retry},
    print_limited,
    timer::{self, TimerState},
    Address, Process,
};

asr::async_main!(stable);
asr::panic_handler!();

// ─────────────────────────────────────────────────────────────────────────────
// User-visible settings
// Requires `features = ["derive"]` in Cargo.toml for the asr crate.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(asr::settings::Gui)]
struct Settings {
    /// Title Screen Delay
    /// ON  → start the timer when the emulator resets (frame counter ≤ 3).
    /// OFF → start the timer when the game engine reaches sub-state 8.
    #[default = false]
    title_screen_delay: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Pointer chain → NES RAM base (unchanged from original)
// ─────────────────────────────────────────────────────────────────────────────

const MODULE: &str = "MesenCore.so";
const RVA: u64 = 0xc541b0;
const HOPS: [u64; 3] = [0x00, 0x40, 0x28];

// ─────────────────────────────────────────────────────────────────────────────
// Pointer chain → emulator frame counter
//
// HOW TO FILL THESE IN:
//   1. Find the absolute address of the frame counter.
//      In scanmem: search for a value that increments by exactly 1 per frame
//      while the game is paused/running.  Alternatively, check Mesen2 RTA's
//      "Current Frame" display and scan for that value.
//
//   2. With Mesen still open at the *same* address, run:
//        python3 find_chain.py <pid> <frame_counter_addr_hex>
//      (no subtract-offset argument — the frame counter address IS the target)
//
//   3. Copy the reported RVA into FC_RVA and the hops into FC_HOPS.
//      IMPORTANT: also change the array length [u64; N] to match the number
//      of hops printed by the script.
//
//   4. Set FC_CHAIN_READY = true.
//
// Until step 4 is done, resolve_frame_counter always returns None and the
// title_screen_delay toggle has no effect (safe to ship in the meantime).
// ─────────────────────────────────────────────────────────────────────────────

const FC_CHAIN_READY: bool = false;

// ↓ replace with the values find_chain.py reports
const FC_RVA: u64 = 0x0;
// ↓ replace values AND change the array length [u64; N] to match your chain
const FC_HOPS: [u64; 2] = [0x0, 0x0];

// The frame counter in Mesen2 is typically a u32.
// If resolve_frame_counter returns obviously wrong values (e.g. always huge),
// change every `u32` in that function to `u64` and try again.

// ─────────────────────────────────────────────────────────────────────────────
// NES CPU RAM field offsets
// ─────────────────────────────────────────────────────────────────────────────

const SCREEN_TIMER: u64 = 0x07A0;
const WORLD_NUM: u64 = 0x075F;
const LEVEL_NUM: u64 = 0x075C;
const GAME_ENGINE_SUB: u64 = 0x000E;
const OPER_MODE: u64 = 0x0770;
const OPER_MODE_TASK: u64 = 0x0772;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn valid_ptr(v: u64) -> bool {
    v >= 0x1_0000 && v <= 0x7fff_ffff_ffff
}

/// Re-walks the NES RAM pointer chain on every tick; never operates on a
/// stale address.
fn resolve_nes_ram(p: &Process) -> Option<Address> {
    let base = p.get_module_address(MODULE).ok()?;
    let mut ptr: u64 = p.read(base + RVA).ok()?;
    if !valid_ptr(ptr) {
        return None;
    }
    for hop in HOPS {
        ptr = p.read(Address::new(ptr + hop)).ok()?;
        if !valid_ptr(ptr) {
            return None;
        }
    }
    Some(Address::new(ptr))
}

/// Re-walks the frame-counter pointer chain every tick.
/// Returns None if FC_CHAIN_READY is false or the chain can't be resolved.
fn resolve_frame_counter(p: &Process) -> Option<u32> {
    if !FC_CHAIN_READY {
        return None;
    }
    let base = p.get_module_address(MODULE).ok()?;
    let mut ptr: u64 = p.read(base + FC_RVA).ok()?;
    if !valid_ptr(ptr) {
        return None;
    }
    for hop in FC_HOPS {
        ptr = p.read(Address::new(ptr + hop)).ok()?;
        if !valid_ptr(ptr) {
            return None;
        }
    }
    // ptr is now the address holding the frame count value.
    p.read::<u32>(Address::new(ptr)).ok()
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-tick NES RAM snapshot
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct Snap {
    screen_timer: u8,
    world_num: u8,
    level_num: u8,
    game_engine_sub: u8,
    oper_mode: u8,
    oper_mode_task: u8,
}

fn read_snap(p: &Process, nes: Address) -> Option<Snap> {
    Some(Snap {
        screen_timer:    p.read(nes + SCREEN_TIMER).ok()?,
         world_num:       p.read(nes + WORLD_NUM).ok()?,
         level_num:       p.read(nes + LEVEL_NUM).ok()?,
         game_engine_sub: p.read(nes + GAME_ENGINE_SUB).ok()?,
         oper_mode:       p.read(nes + OPER_MODE).ok()?,
         oper_mode_task:  p.read(nes + OPER_MODE_TASK).ok()?,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Main loop
// ─────────────────────────────────────────────────────────────────────────────

async fn main() {
    asr::set_tick_rate(60.0);

    // Register settings once; the handle is updated in-place each tick via
    // settings.update() so user toggles take effect immediately.
    let mut settings = Settings::register();

    loop {
        let process = retry(|| Process::attach("Mesen")).await;

        // ── Per-process-attach state ──────────────────────────────────────────
        // Survives in-game resets and deaths without closing the emulator.
        let mut current_world: u8 = 0;
        let mut current_level: u8 = 0;
        let mut starting = false;
        let mut prev: Option<Snap> = None;
        // prev_frame is tracked regardless of whether title_screen_delay is ON
        // so that toggling the setting mid-session works immediately.
        let mut prev_frame: Option<u32> = None;
        let mut log_throttle: u32 = 0;

        while process.is_open() {
            // Poll for live setting changes made in the LiveSplit One UI.
            settings.update();

            let Some(nes) = resolve_nes_ram(&process) else {
                next_tick().await;
                continue;
            };
            let Some(curr) = read_snap(&process, nes) else {
                next_tick().await;
                continue;
            };

            // Always try to read the frame counter; it returns None when the
            // chain hasn't been configured yet (FC_CHAIN_READY = false).
            let curr_frame = resolve_frame_counter(&process);

            // ── Diagnostics ───────────────────────────────────────────────────
            // If om/wn/ln/ges never change while you play, the NES RAM chain
            // is stale.  If fc is always None, FC_CHAIN_READY is still false.
            // Comment out this block once values are confirmed live.
            log_throttle += 1;
            if log_throttle >= 60 {
                log_throttle = 0;
                print_limited::<128>(&format_args!(
                    "om={} wn={} ln={} ges={} st={} omt={} fc={:?}",
                    curr.oper_mode,
                    curr.world_num,
                    curr.level_num,
                    curr.game_engine_sub,
                    curr.screen_timer,
                    curr.oper_mode_task,
                    curr_frame,
                ));
            }

            if let Some(old) = prev {
                // Returning to the title screen resets per-attempt tracking so
                // the next run starts cleanly, even across soft resets.
                if curr.oper_mode == 0 && old.oper_mode != 0 {
                    current_world = 0;
                    current_level = 0;
                    starting = false;
                }

                match timer::state() {
                    TimerState::NotRunning => {
                        if settings.title_screen_delay {
                            // ── Title-screen-delay mode ───────────────────────
                            // The emulator resets the frame counter to 0 on a
                            // hard reset.  We detect this as: the counter
                            // decreased AND landed at ≤ 3 (a small window
                            // so we don't need to hit frame 0 exactly).
                            //
                            // prev_frame being Some ensures we've had at least
                            // one prior tick, preventing a false fire on startup.
                            if let (Some(cf), Some(pf)) = (curr_frame, prev_frame) {
                                if cf < pf && cf <= 3 {
                                    timer::start();
                                }
                            }
                        } else {
                            // ── Original no-delay mode ────────────────────────
                            if curr.oper_mode == 1 && old.oper_mode == 0 {
                                current_world = curr.world_num;
                                current_level = curr.level_num;
                                starting = true;
                            }

                            if starting
                                && curr.game_engine_sub == 8
                                && old.game_engine_sub < 8
                                && curr.oper_mode == 1
                                && curr.oper_mode_task >= 3
                                {
                                    starting = false;
                                    timer::start();
                                }
                        }
                    }

                    TimerState::Running => {
                        if curr.world_num >= 7 && curr.oper_mode == 2 && old.oper_mode != 2 {
                            // Axe grabbed — end of game.
                            timer::split();
                        } else if curr.world_num > current_world
                            || curr.level_num > current_level
                            {
                                let level_started = (curr.game_engine_sub == 7
                                || curr.game_engine_sub == 8)
                                && old.game_engine_sub < curr.game_engine_sub;

                                let used_warp = curr.world_num > current_world + 1
                                || (curr.world_num == current_world + 1
                                && current_level < 3);

                                let should_split = if used_warp {
                                    level_started
                                } else {
                                    curr.screen_timer >= 6 && old.screen_timer == 0
                                };

                                if should_split {
                                    current_world = curr.world_num;
                                    current_level = curr.level_num;
                                    timer::split();
                                }
                            }
                    }

                    _ => {}
                }
            }

            prev = Some(curr);
            prev_frame = curr_frame;
            next_tick().await;
        }
    }
}
