//! Chronological timestamp block operations with arbitrary-depth precision and limit scaling.

#[cfg(all(feature = "sys-clock", feature = "std"))]
use core::sync::atomic::{AtomicU64, Ordering};

use crate::base62::{self, MAX_U64_BASE62_VAL};
use crate::block::{Block, BlockType};
use crate::error::{Base62Error, BlockError, BufferError};

pub const DAYS_PER_YEAR_MAX: u64 = 366;
pub const SECS_PER_DAY: u64 = 86_400;
pub const SECS_PER_CANONICAL_YEAR: u64 = DAYS_PER_YEAR_MAX * SECS_PER_DAY; // 31,622,400 secs/yr
pub const FRACTION_BASE: u64 = 1_000;

/// Base epoch anchor: Year 2000 CE.
pub const YEAR_BASE: u64 = 2000;

/// Base block 0 capacity: 6 Base62 characters ($62^6 - 1 = 56,800,235,583$).
pub const INSTANCE_0_WIDTH: usize = 6;
pub const INSTANCE_0_MAX_VAL: u64 = 56_800_235_583;

/// Year modulus per base block 0 (~1,796 years).
pub const YEAR_MODULUS_TIER: u64 = (INSTANCE_0_MAX_VAL + 1) / SECS_PER_CANONICAL_YEAR; // 1,796

/// Maximum value for a 2-character Base62 block ($62^2 - 1 = 3,843$).
/// All subsecond fractions (0..999) fit comfortably in 2 characters.
pub const SUBSECOND_2CHAR_MAX: u64 = 3_843;

#[cfg(all(feature = "sys-clock", feature = "std"))]
static SUB_NANO_COUNTER: AtomicU64 = AtomicU64::new(0);

#[cfg(all(feature = "sys-clock", feature = "std"))]
#[inline]
fn init_sub_nano_seed() -> u64 {
    let local_var = 0u64;
    let stack_entropy = (&local_var as *const u64 as usize) as u64;
    let ptr_entropy = (&SUB_NANO_COUNTER as *const AtomicU64 as usize) as u64;

    #[cfg(feature = "std")]
    let (time_entropy, pid_entropy) = {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let p = std::process::id() as u64;
        (t, p)
    };

    #[cfg(not(feature = "std"))]
    let (time_entropy, pid_entropy): (u64, u64) = (0x517c_c1b7_2722_0a95, 0x9e37_79b9);

    let mut seed = ptr_entropy
        ^ stack_entropy.rotate_left(21)
        ^ time_entropy.rotate_left(42)
        ^ pid_entropy.rotate_left(13)
        ^ 0x9e37_79b9_7f4a_7c15;

    // SplitMix64 mixing
    seed ^= seed >> 30;
    seed = seed.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    seed ^= seed >> 27;
    seed = seed.wrapping_mul(0x94d0_49bb_1331_11eb);
    seed ^ (seed >> 31)
}

/// Precision tiers scaling indefinitely with every additional instance in an identifier.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TimePrecision {
    /// Instance 0: Date + Time-of-Day in seconds (~1s, Years 2000..3796 CE).
    Seconds,
    /// Instance 1: Milliseconds (~1ms, Years 2000..3.79M CE).
    Milliseconds,
    /// Instance 2: Microseconds (~1µs, Years 2000..3.79B CE).
    Microseconds,
    /// Instance 3: Nanoseconds (~1ns, Years 2000..3.79 Trillion CE).
    Nanoseconds,
    /// Instance 4: Picoseconds (~1ps, Years 2000..3.79 Quadrillion CE).
    Picoseconds,
    /// Instance 5: Femtoseconds (~1fs, Years 2000..3.79 Quintillion CE).
    Femtoseconds,
    /// Instance 6+: Attoseconds (~1as, Cosmic scale).
    Attoseconds,
}

impl TimePrecision {
    #[inline]
    pub const fn from_instance(instance: usize) -> Self {
        match instance {
            0 => Self::Seconds,
            1 => Self::Milliseconds,
            2 => Self::Microseconds,
            3 => Self::Nanoseconds,
            4 => Self::Picoseconds,
            5 => Self::Femtoseconds,
            _ => Self::Attoseconds,
        }
    }
}

/// Decoded civil calendar datetime representation with arbitrary sub-second fractions.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct DateTime {
    pub year: u64,
    pub month: u8,
    pub day: u8,
    pub day_of_year: u16,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    /// Subsecond fraction parts in powers of 1000:
    /// `[millis, micros_rem, nanos_rem, picos_rem, femtos_rem, attos_rem]`
    pub subsecond_parts: [u16; 7],
    pub precision: TimePrecision,
}

impl DateTime {
    #[inline]
    pub fn millisecond(&self) -> u16 {
        self.subsecond_parts[0]
    }

    #[inline]
    pub fn microsecond(&self) -> u16 {
        self.subsecond_parts[1]
    }

    #[inline]
    pub fn nanosecond(&self) -> u32 {
        (self.subsecond_parts[0] as u32 * 1_000_000)
            + (self.subsecond_parts[1] as u32 * 1_000)
            + (self.subsecond_parts[2] as u32)
    }

    #[inline]
    pub fn picosecond_rem(&self) -> u16 {
        self.subsecond_parts[3]
    }

    #[inline]
    pub fn femtosecond_rem(&self) -> u16 {
        self.subsecond_parts[4]
    }

    #[inline]
    pub fn attosecond_rem(&self) -> u16 {
        self.subsecond_parts[5]
    }
}

#[inline]
pub const fn is_leap_year(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

#[inline]
pub const fn days_in_month(year: u64, month: u8) -> u8 {
    match month {
        1 => 31,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        3 => 31,
        4 => 30,
        5 => 31,
        6 => 30,
        7 => 31,
        8 => 31,
        9 => 30,
        10 => 31,
        11 => 30,
        12 => 31,
        _ => 0,
    }
}

pub fn ymd_to_doy(year: u64, month: u8, day: u8) -> Result<u16, BlockError> {
    if !(1..=12).contains(&month) {
        return Err(BlockError::InvalidLength(month as usize));
    }
    let dim = days_in_month(year, month);
    if day < 1 || day > dim {
        return Err(BlockError::InvalidLength(day as usize));
    }
    let mut doy = 0u16;
    let mut m = 1;
    while m < month {
        doy += days_in_month(year, m) as u16;
        m += 1;
    }
    doy += day as u16;
    Ok(doy)
}

pub fn doy_to_ymd(year: u64, mut doy: u16) -> (u64, u8, u8) {
    let max_doy = if is_leap_year(year) { 366 } else { 365 };
    if doy == 0 {
        doy = 1;
    } else if doy > max_doy {
        doy = max_doy;
    }
    let mut month = 1;
    while month <= 12 {
        let dim = days_in_month(year, month) as u16;
        if doy <= dim {
            return (year, month, doy as u8);
        }
        doy -= dim;
        month += 1;
    }
    (year, 12, 31)
}

pub fn unix_days_to_ymd(days: i64) -> (u64, u8, u8) {
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1024 + doe / 1461 - doe / 14241) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u8;
    let year = if m <= 2 { y + 1 } else { y };
    (year as u64, m, d)
}

/// Type 2: Arbitrary precision and range-scalable chronological timestamp block.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Time(pub u64);

impl Time {
    #[inline]
    pub fn new(val: u64) -> Result<Self, BlockError> {
        if val > MAX_U64_BASE62_VAL {
            return Err(BlockError::Base62(Base62Error::Overflow));
        }
        Ok(Self(val))
    }

    /// Packs Instance 0: `((Year - 2000) % 1796) * (366 * 86400) + (DOY - 1) * 86400 + SecOfDay`
    pub fn from_datetime_instance0(
        year: u64,
        doy: u16,
        sec_of_day: u32,
    ) -> Result<Self, BlockError> {
        let y_offset = year.saturating_sub(YEAR_BASE);
        let y_mod = y_offset % YEAR_MODULUS_TIER;
        let day_idx = (doy.saturating_sub(1) as u64).min(DAYS_PER_YEAR_MAX - 1);
        let sec = (sec_of_day as u64).min(SECS_PER_DAY - 1);

        let packed = (y_mod * SECS_PER_CANONICAL_YEAR) + (day_idx * SECS_PER_DAY) + sec;
        Self::new(packed)
    }

    /// Packs Subsecond Extension Instance $k \ge 1$:
    /// `YearTier_k * 1000 + SubsecondPart_k`
    pub fn from_subsecond_tier(
        year: u64,
        tier_index: usize,
        fraction_part_1000: u16,
    ) -> Result<Self, BlockError> {
        let y_offset = year.saturating_sub(YEAR_BASE);
        let mut divisor = YEAR_MODULUS_TIER;
        let mut i = 1;
        while i < tier_index {
            divisor = divisor.saturating_mul(FRACTION_BASE);
            i += 1;
        }
        let y_tier = (y_offset / divisor) % FRACTION_BASE;
        let frac = (fraction_part_1000 as u64).min(FRACTION_BASE - 1);
        let packed = (y_tier * FRACTION_BASE) + frac;
        Self::new(packed)
    }

    #[inline]
    pub fn value(&self) -> u64 {
        self.0
    }

    #[cfg(all(feature = "sys-clock", feature = "std"))]
    pub fn now_instance(instance: usize) -> Result<Self, BlockError> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| BlockError::Base62(Base62Error::Overflow))?;

        let total_secs = now.as_secs();
        let subsec_nanos = now.subsec_nanos();

        let unix_days = (total_secs / 86_400) as i64;
        let (year, month, day) = unix_days_to_ymd(unix_days);
        let doy = ymd_to_doy(year, month, day)?;
        let sec_of_day = (total_secs % 86_400) as u32;

        if instance == 0 {
            Self::from_datetime_instance0(year, doy, sec_of_day)
        } else {
            let millis = (subsec_nanos / 1_000_000) as u16;
            let micros = ((subsec_nanos / 1_000) % 1_000) as u16;
            let nanos = (subsec_nanos % 1_000) as u16;

            let fraction_1000 = match instance {
                1 => millis,
                2 => micros,
                3 => nanos,
                _ => {
                    let cur = SUB_NANO_COUNTER.load(Ordering::Relaxed);
                    if cur == 0 {
                        let _ = SUB_NANO_COUNTER.compare_exchange(
                            0,
                            init_sub_nano_seed(),
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                        );
                    }
                    let step = SUB_NANO_COUNTER.fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed);
                    let mut hash = step
                        ^ (subsec_nanos as u64).rotate_left(13)
                        ^ (instance as u64).rotate_left(29);
                    hash ^= hash >> 30;
                    hash = hash.wrapping_mul(0xbf58_476d_1ce4_e5b9);
                    hash ^= hash >> 27;
                    (hash % FRACTION_BASE) as u16
                }
            };

            Self::from_subsecond_tier(year, instance, fraction_1000)
        }
    }

    #[cfg(all(feature = "sys-clock", feature = "std"))]
    pub fn now() -> Result<Self, BlockError> {
        Self::now_instance(0)
    }
}

impl Block for Time {
    const TYPE: BlockType = BlockType::Time;

    #[inline]
    fn encode(&self, dest: &mut [u8]) -> Result<usize, BufferError> {
        if self.0 <= SUBSECOND_2CHAR_MAX {
            base62::encode_u64_fixed_into(self.0, 2, dest)
        } else if self.0 <= INSTANCE_0_MAX_VAL {
            base62::encode_u64_fixed_into(self.0, INSTANCE_0_WIDTH, dest)
        } else {
            base62::encode_u64_into(self.0, dest)
        }
    }

    #[inline]
    fn decode(raw: &str) -> Result<Self, BlockError> {
        let val = base62::decode_u64(raw)?;
        Ok(Self(val))
    }
}
