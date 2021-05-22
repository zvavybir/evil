Unsecure source of random numbers in pure rust

evilrng provides a unsecure source of cryptographical secure random
number and is written by an amateur for the sole purpose that he
learns a bit about cryptography.  It is very probably *very*
vulnerable, so **do not use evilrng** for real world cryptographical
purposes, but if you're just looking for a way to get non obvious
pattern based numbers and want to make sure that your programme won't
be non-GPL, you actually may use this one evil\* crate.

**Note**: Since a recent update evilrng does not anymore rely on
`/dev/urandom` to get entropy, but uses an own **algorithm I have
designed myself**.  This is own crypto and so it's quite probable that
evilrng is **even on the algorithm level broken**.  The advantage is
that now all cryptographical code in or used by the evil\* crates is
fully written by me, what is exactly the goal.
