#include "bitcoin.h"
#include <cstring>
#include "core/crypto/crypto_core.h"
#include "core/io/file_access.h"

namespace godot {

const char* BIP39_WORDLIST[] = {
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse",
    "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act",
    "action", "actor", "actress", "actual", "adapt", "add", "addict", "address", "adjust", "admit",
    "adult", "advance", "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
    "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol", "alert",
    "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already", "also", "alter",
    "always", "amateur", "amazing", "among", "amount", "amused", "analyst", "anchor", "ancient", "anger",
    "angle", "angry", "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
    "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april", "arch", "arctic",
    "area", "arena", "argue", "arm", "armed", "armor", "army", "around", "arrange", "arrest",
    "arrive", "arrow", "art", "artefact", "artist", "artwork", "ask", "aspect", "assault", "asset",
    "assist", "assume", "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction",
    "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado", "avoid", "awake",
    "aware", "away", "awesome", "awful", "awkward", "axis", "baby", "bachelor", "bacon", "badge",
    "bag", "balance", "balcony", "ball", "bamboo", "banana", "banner", "bar", "barely", "bargain",
    "barrel", "base", "basic", "basket", "battle", "beach", "bean", "beauty", "because", "become",
    "beef", "before", "begin", "behave", "behind", "believe", "below", "belt", "bench", "benefit",
    "best", "betray", "better", "between", "beyond", "bicycle", "bid", "bike", "bind", "biology",
    "bird", "birth", "bitter", "black", "blade", "blame", "blanket", "blast", "bleak", "bless",
    "blind", "blood", "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body",
    "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring", "borrow", "boss",
    "bottom", "bounce", "box", "boy", "bracket", "brain", "brand", "brass", "brave", "bread",
    "breeze", "brick", "bridge", "brief", "bright", "bring", "brisk", "broccoli", "broken", "bronze",
    "broom", "brother", "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb",
    "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus", "business", "busy",
    "butter", "buyer", "buzz", "cabbage", "cabin", "cable", "cactus", "cage", "cake", "call",
    "calm", "camera", "camp", "can", "canal", "cancel", "candy", "cannon", "canoe", "canvas",
    "canyon", "capable", "capital", "captain", "car", "carbon", "card", "cargo", "carpet", "carry",
    "cart", "case", "cash", "casino", "castle", "casual", "cat", "catalog", "catch", "category",
    "cattle", "caught", "cause", "caution", "cave", "ceiling", "celery", "cement", "census", "century",
    "cereal", "certain", "chair", "chalk", "champion", "change", "chaos", "chapter", "charge", "chase",
    "chat", "cheap", "check", "cheese", "chef", "cherry", "chest", "chicken", "chief", "child",
    "chimney", "choice", "choose", "chronic", "chuckle", "chunk", "churn", "cigar", "cinnamon", "circle",
    "citizen", "city", "civil", "claim", "clap", "clarify", "claw", "clay", "clean", "clerk",
    "clever", "click", "client", "cliff", "climb", "clinic", "clip", "clock", "clog", "close",
    "cloth", "cloud", "clown", "club", "clump", "cluster", "clutch", "coach", "coast", "coconut",
    "code", "coffee", "coil", "coin", "collect", "color", "column", "combine", "come", "comfort",
    "comic", "common", "company", "concert", "conduct", "confirm", "congress", "connect", "consider", "control",
    "convince", "cook", "cool", "copper", "copy", "coral", "core", "corn", "correct", "cost",
    "cotton", "couch", "country", "couple", "course", "cousin", "cover", "coyote", "crack", "cradle",
    "craft", "cram", "crane", "crash", "crater", "crawl", "crazy", "cream", "credit", "creek",
    "crew", "cricket", "crime", "crisp", "critic", "crop", "cross", "crouch", "crowd", "crucial",
    "cruel", "cruise", "crumble", "crunch", "crush", "cry", "crystal", "cube", "culture", "cup",
    "cupboard", "curious", "current", "curtain", "curve", "cushion", "custom", "cute", "cycle", "dad",
    "damage", "damp", "dance", "danger", "daring", "dash", "daughter", "dawn", "day", "deal",
    "debate", "debris", "decade", "december", "decide", "decline", "decorate", "decrease", "deer", "defense",
    "define", "defy", "degree", "delay", "deliver", "demand", "demise", "denial", "dentist", "deny",
    "depart", "depend", "deposit", "depth", "deputy", "derive", "describe", "desert", "design", "desk",
    "despair", "destroy", "detail", "detect", "develop", "device", "devote", "diagram", "dial", "diamond",
    "diary", "dice", "diesel", "diet", "differ", "digital", "dignity", "dilemma", "dinner", "dinosaur",
    "direct", "dirt", "disagree", "discover", "disease", "dish", "dismiss", "disorder", "display", "distance",
    "divert", "divide", "divorce", "dizzy", "doctor", "document", "dog", "doll", "dolphin", "domain",
    "donate", "donkey", "donor", "door", "dose", "double", "dove", "draft", "dragon", "drama",
    "drastic", "draw", "dream", "dress", "drift", "drill", "drink", "drip", "drive", "drop",
    "drum", "dry", "duck", "dumb", "dune", "during", "dust", "dutch", "duty", "dwarf",
    "dynamic", "eager", "eagle", "early", "earn", "earth", "easily", "east", "easy", "echo",
    "ecology", "economy", "edge", "edit", "educate", "effort", "egg", "eight", "either", "elbow",
    "elder", "electric", "elegant", "element", "elephant", "elevator", "elite", "else", "embark", "embody",
    "embrace", "emerge", "emotion", "employ", "empower", "empty", "enable", "enact", "end", "endless",
    "endorse", "enemy", "energy", "enforce", "engage", "engine", "enhance", "enjoy", "enlist", "enough",
    "enrich", "enroll", "ensure", "enter", "entire", "entry", "envelope", "episode", "equal", "equip",
    "era", "erase", "erode", "erosion", "error", "erupt", "escape", "essay", "essence", "estate",
    "eternal", "ethics", "evidence", "evil", "evoke", "evolve", "exact", "example", "excess", "exchange",
    "excite", "exclude", "excuse", "execute", "exercise", "exhaust", "exhibit", "exile", "exist", "exit",
    "exotic", "expand", "expect", "expire", "explain", "expose", "express", "extend", "extra", "eye",
    "eyebrow", "fabric", "face", "faculty", "fade", "faint", "faith", "fall", "false", "fame",
    "family", "famous", "fan", "fancy", "fantasy", "farm", "fashion", "fat", "fatal", "father",
    "fatigue", "fault", "favorite", "feature", "february", "federal", "fee", "feed", "feel", "female",
    "fence", "festival", "fetch", "fever", "few", "fiber", "fiction", "field", "figure", "file",
    "film", "filter", "final", "find", "fine", "finger", "finish", "fire", "firm", "first",
    "fiscal", "fish", "fit", "fitness", "fix", "flag", "flame", "flash", "flat", "flavor",
    "flee", "flight", "flip", "float", "flock", "floor", "flower", "fluid", "flush", "fly",
    "foam", "focus", "fog", "foil", "fold", "follow", "food", "foot", "force", "forest",
    "forget", "fork", "fortune", "forum", "forward", "fossil", "foster", "found", "fox", "fragile",
    "frame", "frequent", "fresh", "friend", "fringe", "frog", "front", "frost", "frown", "frozen",
    "fruit", "fuel", "fun", "funny", "furnace", "fury", "future", "gadget", "gain", "galaxy",
    "gallery", "game", "gap", "garage", "garbage", "garden", "garlic", "garment", "gas", "gasp",
    "gate", "gather", "gauge", "gaze", "general", "genius", "genre", "gentle", "genuine", "gesture",
    "ghost", "giant", "gift", "giggle", "ginger", "giraffe", "girl", "give", "glad", "glance",
    "glare", "glass", "glide", "glimpse", "globe", "gloom", "glory", "glove", "glow", "glue",
    "goat", "goddess", "gold", "good", "goose", "gorilla", "gospel", "gossip", "govern", "gown",
    "grab", "grace", "grain", "grant", "grape", "grass", "gravity", "great", "green", "grid",
    "grief", "grit", "grocery", "group", "grow", "grunt", "guard", "guess", "guide", "guilt",
    "guitar", "gun", "gym", "habit", "hair", "half", "hammer", "hamster", "hand", "happy",
    "harbor", "hard", "harsh", "harvest", "hat", "have", "hawk", "hazard", "head", "health",
    "heart", "heavy", "hedgehog", "height", "hello", "helmet", "help", "hen", "hero", "hidden",
    "high", "hill", "hint", "hip", "hire", "history", "hobby", "hockey", "hold", "hole",
    "holiday", "hollow", "home", "honey", "hood", "hope", "horn", "horror", "horse", "hospital",
    "host", "hotel", "hour", "hover", "hub", "huge", "human", "humble", "humor", "hundred",
    "hungry", "hunt", "hurdle", "hurry", "hurt", "husband", "hybrid", "ice", "icon", "idea",
    "identify", "idle", "ignore", "ill", "illegal", "illness", "image", "imitate", "immense", "immune",
    "impact", "impose", "improve", "impulse", "inch", "include", "income", "increase", "index", "indicate",
    "indoor", "industry", "infant", "inflict", "inform", "inhale", "inherit", "initial", "inject", "injury",
    "inmate", "inner", "innocent", "input", "inquiry", "insane", "insect", "inside", "inspire", "install",
    "intact", "interest", "into", "invest", "invite", "involve", "iron", "island", "isolate", "issue",
    "item", "ivory", "jacket", "jaguar", "jar", "jazz", "jealous", "jeans", "jelly", "jewel",
    "job", "join", "joke", "journey", "joy", "judge", "juice", "jump", "jungle", "junior",
    "junk", "just", "kangaroo", "keen", "keep", "ketchup", "key", "kick", "kid", "kidney",
    "kind", "kingdom", "kiss", "kit", "kitchen", "kite", "kitten", "kiwi", "knee", "knife",
    "knock", "know", "lab", "label", "labor", "ladder", "lady", "lake", "lamp", "language",
    "laptop", "large", "later", "latin", "laugh", "laundry", "lava", "law", "lawn", "lawsuit",
    "layer", "lazy", "leader", "leaf", "learn", "leave", "lecture", "left", "leg", "legal",
    "legend", "leisure", "lemon", "lend", "length", "lens", "leopard", "lesson", "letter", "level",
    "liar", "liberty", "library", "license", "life", "lift", "light", "like", "limb", "limit",
    "link", "lion", "liquid", "list", "little", "live", "lizard", "load", "loan", "lobster",
    "local", "lock", "logic", "lonely", "long", "loop", "lottery", "loud", "lounge", "love",
    "loyal", "lucky", "luggage", "lumber", "lunar", "lunch", "luxury", "lyrics", "machine", "mad",
    "magic", "magnet", "maid", "mail", "main", "major", "make", "mammal", "man", "manage",
    "mandate", "mango", "mansion", "manual", "maple", "marble", "march", "margin", "marine", "market",
    "marriage", "mask", "mass", "master", "match", "material", "math", "matrix", "matter", "maximum",
    "maze", "meadow", "mean", "measure", "meat", "mechanic", "medal", "media", "melody", "melt",
    "member", "memory", "mention", "menu", "mercy", "merge", "merit", "merry", "mesh", "message",
    "metal", "method", "middle", "midnight", "milk", "million", "mimic", "mind", "minimum", "minor",
    "minute", "miracle", "mirror", "misery", "miss", "mistake", "mix", "mixed", "mixture", "mobile",
    "model", "modify", "mom", "moment", "monitor", "monkey", "monster", "month", "moon", "moral",
    "more", "morning", "mosquito", "mother", "motion", "motor", "mountain", "mouse", "move", "movie",
    "much", "muffin", "mule", "multiply", "muscle", "museum", "mushroom", "music", "must", "mutual",
    "myself", "mystery", "myth", "naive", "name", "napkin", "narrow", "nasty", "nation", "nature",
    "near", "neck", "need", "negative", "neglect", "neither", "nephew", "nerve", "nest", "net",
    "network", "neutral", "never", "news", "next", "nice", "night", "noble", "noise", "nominee",
    "noodle", "normal", "north", "nose", "notable", "note", "nothing", "notice", "novel", "now",
    "nuclear", "number", "nurse", "nut", "oak", "obey", "object", "oblige", "obscure", "observe",
    "obtain", "obvious", "occur", "ocean", "october", "odor", "off", "offer", "office", "often",
    "oil", "okay", "old", "olive", "olympic", "omit", "once", "one", "onion", "online",
    "only", "open", "opera", "opinion", "oppose", "option", "orange", "orbit", "orchard", "order",
    "ordinary", "organ", "orient", "original", "orphan", "ostrich", "other", "outdoor", "outer", "output",
    "outside", "oval", "oven", "over", "own", "owner", "oxygen", "oyster", "ozone", "pact",
    "paddle", "page", "pair", "palace", "palm", "panda", "panel", "panic", "panther", "paper",
    "parade", "parent", "park", "parrot", "party", "pass", "patch", "path", "patient", "patrol",
    "pattern", "pause", "pave", "payment", "peace", "peanut", "pear", "peasant", "pelican", "pen",
    "penalty", "pencil", "people", "pepper", "perfect", "permit", "person", "pet", "phone", "photo",
    "phrase", "physical", "piano", "picnic", "picture", "piece", "pig", "pigeon", "pill", "pilot",
    "pink", "pioneer", "pipe", "pistol", "pitch", "pizza", "place", "planet", "plastic", "plate",
    "play", "please", "pledge", "pluck", "plug", "plunge", "poem", "poet", "point", "polar",
    "pole", "police", "pond", "pony", "pool", "popular", "portion", "position", "possible", "post",
    "potato", "pottery", "poverty", "powder", "power", "practice", "praise", "predict", "prefer", "prepare",
    "present", "pretty", "prevent", "price", "pride", "primary", "print", "priority", "prison", "private",
    "prize", "problem", "process", "produce", "profit", "program", "project", "promote", "proof", "property",
    "prosper", "protect", "proud", "provide", "public", "pudding", "pull", "pulp", "pulse", "pumpkin",
    "punch", "pupil", "puppy", "purchase", "purity", "purpose", "purse", "push", "put", "puzzle",
    "pyramid", "quality", "quantum", "quarter", "question", "quick", "quit", "quiz", "quote", "rabbit",
    "raccoon", "race", "rack", "radar", "radio", "rail", "rain", "raise", "rally", "ramp",
    "ranch", "random", "range", "rapid", "rare", "rate", "rather", "raven", "raw", "razor",
    "ready", "real", "reason", "rebel", "rebuild", "recall", "receive", "recipe", "record", "recycle",
    "reduce", "reflect", "reform", "refuse", "region", "regret", "regular", "reject", "relax", "release",
    "relief", "rely", "remain", "remember", "remind", "remove", "render", "renew", "rent", "reopen",
    "repair", "repeat", "replace", "report", "require", "rescue", "resemble", "resist", "resource", "response",
    "result", "retire", "retreat", "return", "reunion", "reveal", "review", "reward", "rhythm", "rib",
    "ribbon", "rice", "rich", "ride", "ridge", "rifle", "right", "rigid", "ring", "riot",
    "ripple", "risk", "ritual", "rival", "river", "road", "roast", "robot", "robust", "rocket",
    "romance", "roof", "rookie", "room", "rose", "rotate", "rough", "round", "route", "royal",
    "rubber", "rude", "rug", "rule", "run", "runway", "rural", "sad", "saddle", "sadness",
    "safe", "sail", "salad", "salmon", "salon", "salt", "salute", "same", "sample", "sand",
    "satisfy", "satoshi", "sauce", "sausage", "save", "say", "scale", "scan", "scare", "scatter",
    "scene", "scheme", "school", "science", "scissors", "scorpion", "scout", "scrap", "screen", "script",
    "scrub", "sea", "search", "season", "seat", "second", "secret", "section", "security", "seed",
    "seek", "segment", "select", "sell", "seminar", "senior", "sense", "sentence", "series", "service",
    "session", "settle", "setup", "seven", "shadow", "shaft", "shallow", "share", "shed", "shell",
    "sheriff", "shield", "shift", "shine", "ship", "shiver", "shock", "shoe", "shoot", "shop",
    "short", "shoulder", "shove", "shrimp", "shrug", "shuffle", "shy", "sibling", "sick", "side",
    "siege", "sight", "sign", "silent", "silk", "silly", "silver", "similar", "simple", "since",
    "sing", "siren", "sister", "situate", "six", "size", "skate", "sketch", "ski", "skill",
    "skin", "skirt", "skull", "slab", "slam", "sleep", "slender", "slice", "slide", "slight",
    "slim", "slogan", "slot", "slow", "slush", "small", "smart", "smile", "smoke", "smooth",
    "snack", "snake", "snap", "sniff", "snow", "soap", "soccer", "social", "sock", "soda",
    "soft", "solar", "soldier", "solid", "solution", "solve", "someone", "song", "soon", "sorry",
    "sort", "soul", "sound", "soup", "source", "south", "space", "spare", "spatial", "spawn",
    "speak", "special", "speed", "spell", "spend", "sphere", "spice", "spider", "spike", "spin",
    "spirit", "split", "spoil", "sponsor", "spoon", "sport", "spot", "spray", "spread", "spring",
    "spy", "square", "squeeze", "squirrel", "stable", "stadium", "staff", "stage", "stairs", "stamp",
    "stand", "start", "state", "stay", "steak", "steel", "stem", "step", "stereo", "stick",
    "still", "sting", "stock", "stomach", "stone", "stool", "story", "stove", "strategy", "street",
    "strike", "strong", "struggle", "student", "stuff", "stumble", "style", "subject", "submit", "subway",
    "success", "such", "sudden", "suffer", "sugar", "suggest", "suit", "summer", "sun", "sunny",
    "sunset", "super", "supply", "supreme", "sure", "surface", "surge", "surprise", "surround", "survey",
    "suspect", "sustain", "swallow", "swamp", "swap", "swarm", "swear", "sweet", "swift", "swim",
    "swing", "switch", "sword", "symbol", "symptom", "syrup", "system", "table", "tackle", "tag",
    "tail", "talent", "talk", "tank", "tape", "target", "task", "taste", "tattoo", "taxi",
    "teach", "team", "tell", "ten", "tenant", "tennis", "tent", "term", "test", "text",
    "thank", "that", "theme", "then", "theory", "there", "they", "thing", "this", "thought",
    "three", "thrive", "throw", "thumb", "thunder", "ticket", "tide", "tiger", "tilt", "timber",
    "time", "tiny", "tip", "tired", "tissue", "title", "toast", "tobacco", "today", "toddler",
    "toe", "together", "toilet", "token", "tomato", "tomorrow", "tone", "tongue", "tonight", "tool",
    "tooth", "top", "topic", "topple", "torch", "tornado", "tortoise", "toss", "total", "tourist",
    "toward", "tower", "town", "toy", "track", "trade", "traffic", "tragic", "train", "transfer",
    "trap", "trash", "travel", "tray", "treat", "tree", "trend", "trial", "tribe", "trick",
    "trigger", "trim", "trip", "trophy", "trouble", "truck", "true", "truly", "trumpet", "trust",
    "truth", "try", "tube", "tuition", "tumble", "tuna", "tunnel", "turkey", "turn", "turtle",
    "twelve", "twenty", "twice", "twin", "twist", "two", "type", "typical", "ugly", "umbrella",
    "unable", "unaware", "uncle", "uncover", "under", "undo", "unfair", "unfold", "unhappy", "uniform",
    "unique", "unit", "universe", "unknown", "unlock", "until", "unusual", "unveil", "update", "upgrade",
    "uphold", "upon", "upper", "upset", "urban", "urge", "usage", "use", "used", "useful",
    "useless", "usual", "utility", "vacant", "vacuum", "vague", "valid", "valley", "valve", "van",
    "vanish", "vapor", "various", "vast", "vault", "vehicle", "velvet", "vendor", "venture", "venue",
    "verb", "verify", "version", "very", "vessel", "veteran", "viable", "vibrant", "vicious", "victory",
    "video", "view", "village", "vintage", "violin", "virtual", "virus", "visa", "visit", "visual",
    "vital", "vivid", "vocal", "voice", "void", "volcano", "volume", "vote", "voyage", "wage",
    "wagon", "wait", "walk", "wall", "walnut", "want", "warfare", "warm", "warrior", "wash",
    "wasp", "waste", "water", "wave", "way", "wealth", "weapon", "wear", "weasel", "weather",
    "web", "wedding", "weekend", "weird", "welcome", "west", "wet", "whale", "what", "wheat",
    "wheel", "when", "where", "whip", "whisper", "wide", "width", "wife", "wild", "will",
    "win", "window", "wine", "wing", "wink", "winner", "winter", "wire", "wisdom", "wise",
    "wish", "witness", "wolf", "woman", "wonder", "wood", "wool", "word", "work", "world",
    "worry", "worth", "wrap", "wreck", "wrestle", "wrist", "write", "wrong", "yard", "year",
    "yellow", "you", "young", "youth", "zebra", "zero", "zone", "zoo"
};

void BitcoinWallet::_bind_methods() {
    ClassDB::bind_method(D_METHOD("generate_wallet", "input_string", "passphrase"), &BitcoinWallet::generate_wallet, DEFVAL(""));
    ClassDB::bind_method(D_METHOD("derive_seed", "mnemonic", "passphrase"), &BitcoinWallet::derive_seed);
    ClassDB::bind_method(D_METHOD("entropy_to_mnemonic", "entropy"), &BitcoinWallet::entropy_to_mnemonic);
    ClassDB::bind_method(D_METHOD("mnemonic_to_entropy", "mnemonic"), &BitcoinWallet::mnemonic_to_entropy);
    ClassDB::bind_method(D_METHOD("fast_create"), &BitcoinWallet::fast_create);
    ClassDB::bind_method(D_METHOD("is_valid_bip39_word", "word"), &BitcoinWallet::is_valid_mnemonic);
    ClassDB::bind_method(D_METHOD("generate_sidechain_starters", "master_seed_hex", "master_mnemonic", "sidechain_slots"), &BitcoinWallet::generate_sidechain_starters);
}

PackedByteArray BitcoinWallet::sha512(const PackedByteArray &p_data) {
    uint64_t *hash_result = SHA512Hash(const_cast<uint8_t*>(p_data.ptr()), p_data.size());
    PackedByteArray result;
    result.resize(SHA512_HASH_SIZE);
    memcpy(result.ptrw(), hash_result, SHA512_HASH_SIZE);
    free(hash_result);
    return result;
}

PackedByteArray BitcoinWallet::sha256(const PackedByteArray &data) {
    SHA256_CTX ctx;
    PackedByteArray hash;
    hash.resize(SHA256_BLOCK_SIZE);
    sha256_init(&ctx);
    sha256_update(&ctx, data.ptr(), data.size());
    sha256_final(&ctx, hash.ptrw());
    return hash;
}

String BitcoinWallet::bytes_to_binary(const PackedByteArray &bytes) {
    String binary;
    for (int i = 0; i < bytes.size(); i++) {
        for (int j = 7; j >= 0; j--) {
            binary += ((bytes[i] >> j) & 1) ? "1" : "0";
        }
    }
    return binary;
}

String BitcoinWallet::bytes_to_hex(const PackedByteArray &bytes) {
    String hex;
    for (int i = 0; i < bytes.size(); i++) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", bytes[i]);
        hex += buf;
    }
    return hex;
}

int BitcoinWallet::binary_to_int(const String &binary) {
    int result = 0;
    for (int i = 0; i < binary.length(); ++i) {
        result = (result << 1) | (binary[i] == '1' ? 1 : 0);
    }
    return result;
}

PackedByteArray BitcoinWallet::hmac_sha512(const PackedByteArray &key, const PackedByteArray &data) {
    const int BLOCK_SIZE = SHA512_MESSAGE_BLOCK_SIZE;

    PackedByteArray o_key_pad;
    PackedByteArray i_key_pad;
    o_key_pad.resize(BLOCK_SIZE);
    i_key_pad.resize(BLOCK_SIZE);

    PackedByteArray working_key = key;
    if (working_key.size() > BLOCK_SIZE) {
        working_key = sha512(working_key);
    }

    working_key.resize(BLOCK_SIZE);

    for (int i = 0; i < BLOCK_SIZE; i++) {
        o_key_pad.write[i] = working_key[i] ^ 0x5c;
        i_key_pad.write[i] = working_key[i] ^ 0x36;
    }

    PackedByteArray inner_data = i_key_pad;
    inner_data.append_array(data);
    PackedByteArray inner_hash = sha512(inner_data);

    PackedByteArray outer_data = o_key_pad;
    outer_data.append_array(inner_hash);
    return sha512(outer_data);
}

PackedByteArray BitcoinWallet::pbkdf2_hmac_sha512(const String& password, const PackedByteArray& salt, int iterations, int key_length) {
    PackedByteArray result;
    result.resize(key_length);
    
    PackedByteArray password_bytes = password.to_utf8_buffer();
    
    for (int i = 1; i <= (key_length + 63) / 64; i++) {
        PackedByteArray u = salt;
        u.append_array(int_to_bytes(i));
        
        PackedByteArray t = hmac_sha512(password_bytes, u);
        PackedByteArray u_i = t;
        
        for (int j = 1; j < iterations; j++) {
            u_i = hmac_sha512(password_bytes, u_i);
            for (int k = 0; k < t.size(); k++) {
                t.write[k] ^= u_i[k];
            }
        }
        
        int to_copy = MIN(key_length - (i - 1) * 64, 64);
        memcpy(result.ptrw() + (i - 1) * 64, t.ptr(), to_copy);
    }
    
    return result;
}

PackedByteArray BitcoinWallet::int_to_bytes(int value) {
    PackedByteArray result;
    result.resize(4);
    result.write[0] = (value >> 24) & 0xFF;
    result.write[1] = (value >> 16) & 0xFF;
    result.write[2] = (value >> 8) & 0xFF;
    result.write[3] = value & 0xFF;
    return result;
}

bool BitcoinWallet::seed_to_keys(const PackedByteArray& seed, String& strMasterKey, String& strChainCode) {
    if (seed.size() != 64) {
        print_error("Seed size is not 64 bytes");
        return false;
    }

    PackedByteArray hmac_result = hmac_sha512(String("Bitcoin seed").to_utf8_buffer(), seed);
    
    if (hmac_result.size() != 64) {
        print_error("HMAC result size is not 64 bytes");
        return false;
    }

    strMasterKey = "";
    strChainCode = "";

    for (int i = 0; i < 64; ++i) {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", hmac_result[i]);
        
        if (i < 32) {
            strMasterKey += hex;
        } else {
            strChainCode += hex;
        }
    }
    return true;
}

bool BitcoinWallet::is_valid_mnemonic(const String &word) {
    for (int i = 0; i < 2048; ++i) {
        if (word == BIP39_WORDLIST[i]) {
            return true;
        }
    }
    return false;
}

String BitcoinWallet::hex_to_dec(const String &hex) {
    uint64_t value = 0;
    for (int i = 0; i < hex.length(); i++) {
        char c = hex[i];
        value *= 16;

        if (c >= '0' && c <= '9') value += c - '0';
        else if (c >= 'a' && c <= 'f') value += c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') value += c - 'A' + 10;
    }
    return String::num_uint64(value);
}

PackedByteArray BitcoinWallet::hex_to_bytes(const String &hex) {

    PackedByteArray bytes;
    
    for (int i = 0; i < hex.length(); i += 2) {
        bytes.push_back(hex.substr(i, 2).hex_to_int());
    }
    return bytes;
}

PackedByteArray BitcoinWallet::generate_random_bytes(int length) {
    PackedByteArray result;
    result.resize(length);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (int i = 0; i < length; ++i) {
        result.write[i] = static_cast<uint8_t>(dis(gen));
    }

    return result;
}

Dictionary BitcoinWallet::generate_wallet(const String &input_string, const String &passphrase) {
    Dictionary result;

    Vector<String> words = input_string.split(" ");
    if (words.size() == 12) {
        String mnemonic = input_string;
        PackedByteArray entropy = mnemonic_to_entropy(mnemonic);
        if (entropy.is_empty()) {
            result["error"] = "Invalid mnemonic";
            return result;
        }
        
        String entropy_hex = bytes_to_hex(entropy);
        result["bip39_hex"] = entropy_hex;
        result["bip39_bin"] = bytes_to_binary(entropy);

        PackedByteArray hash = sha256(entropy);
        int checksum_length = entropy.size() / 4;
        String checksum = bytes_to_binary(hash).substr(0, checksum_length);
        String csum_hex = bytes_to_hex(hash).substr(0, 1);
        result["bip39_csum"] = checksum;
        result["bip39_csum_hex"] = csum_hex;

        result["hd_key_data"] = bytes_to_hex(hash);
        result["mnemonic"] = mnemonic;
    } else {

        PackedByteArray input_bytes = input_string.to_utf8_buffer();
        PackedByteArray full_hash = sha256(input_bytes);
        PackedByteArray entropy = full_hash.slice(0, 16);

        String entropy_hex = bytes_to_hex(full_hash);
        result["bip39_hex"] = entropy_hex;
        result["bip39_bin"] = bytes_to_binary(entropy);

        PackedByteArray hash = sha256(entropy);
        int checksum_length = entropy.size() / 4;
        String checksum = bytes_to_binary(hash).substr(0, checksum_length);
        String csum_hex = bytes_to_hex(hash).substr(0, 1);
        result["bip39_csum"] = checksum;
        result["bip39_csum_hex"] = csum_hex;

        result["hd_key_data"] = bytes_to_hex(hash);

        String mnemonic = entropy_to_mnemonic(entropy);
        if (mnemonic.is_empty()) {
            result["error"] = "Failed to generate mnemonic";
            return result;
        }
        result["mnemonic"] = mnemonic;
    }

    PackedByteArray seed = derive_seed(result["mnemonic"], passphrase);
    result["seed"] = bytes_to_hex(seed);

    String strMasterKey, strChainCode;
    if (seed_to_keys(seed, strMasterKey, strChainCode)) {
        result["master_key"] = strMasterKey;
        result["chain_code"] = strChainCode;
    } else {
        result["error"] = "Failed to generate keys";
    }

    return result;
}

PackedByteArray BitcoinWallet::derive_seed(const String &mnemonic, const String &passphrase) {
    String salt = "mnemonic" + passphrase;
    PackedByteArray saltBytes = salt.to_utf8_buffer();
    return pbkdf2_hmac_sha512(mnemonic, saltBytes, 2048, 64);
}

String BitcoinWallet::entropy_to_mnemonic(const PackedByteArray& entropy) {
    if (entropy.size() != 16 && entropy.size() != 20 && entropy.size() != 24 && entropy.size() != 28 && entropy.size() != 32) {
        return String();  // Invalid entropy length
    }

    PackedByteArray hash = sha256(entropy);
    int checksum_length = entropy.size() / 4;
    String bits = bytes_to_binary(entropy) + bytes_to_binary(hash).substr(0, checksum_length);

    Vector<String> mnemonic;
    for (int i = 0; i < bits.length(); i += 11) {
        String bit_chunk = bits.substr(i, 11);
        int index = binary_to_int(bit_chunk);
        if (index >= 0 && index < 2048) {  // 2048 is the size of the BIP39 wordlist
            mnemonic.push_back(String(BIP39_WORDLIST[index]));
        } else {
            return String();  // Invalid index
        }
    }
    return String(" ").join(mnemonic);
}

PackedByteArray BitcoinWallet::mnemonic_to_entropy(const String& mnemonic) {
    Vector<String> words = mnemonic.split(" ");
    if (words.size() != 12 && words.size() != 15 && words.size() != 18 && words.size() != 21 && words.size() != 24) {
        return PackedByteArray();  // Invalid mnemonic length
    }

    String bits;
    for (const String& word : words) {
        int index = -1;
        for (int i = 0; i < 2048; ++i) {  // 2048 is the size of the BIP39 wordlist
            if (word == BIP39_WORDLIST[i]) {
                index = i;
                break;
            }
        }
        if (index == -1) {
            return PackedByteArray();  // Invalid word
        }
        bits += String::num_int64(index, 2).pad_zeros(11);
    }

    int checksum_length = bits.length() / 33;
    String entropy_bits = bits.substr(0, bits.length() - checksum_length);
    
    PackedByteArray entropy;
    for (int i = 0; i < entropy_bits.length(); i += 8) {
        entropy.push_back(binary_to_int(entropy_bits.substr(i, 8)));
    }

    PackedByteArray hash = sha256(entropy);
    String generated_checksum = bytes_to_binary(hash).substr(0, checksum_length);
    String provided_checksum = bits.substr(bits.length() - checksum_length);
    
    if (generated_checksum != provided_checksum) {
        return PackedByteArray();  
    }

    return entropy;
}

String BitcoinWallet::fast_create() {
    PackedByteArray bytes = generate_random_bytes(64);
    return bytes_to_hex(bytes);
}

PackedByteArray BitcoinWallet::derive_child_key(const PackedByteArray &parent_key, int index) {

    uint32_t hardened_index = 0x80000000 | index;
    
    PackedByteArray index_bytes;
    index_bytes.resize(4);
    index_bytes.write[0] = (hardened_index >> 24) & 0xFF;
    index_bytes.write[1] = (hardened_index >> 16) & 0xFF;
    index_bytes.write[2] = (hardened_index >> 8) & 0xFF;
    index_bytes.write[3] = hardened_index & 0xFF;

    PackedByteArray data = parent_key;
    data.append_array(index_bytes);

    return hmac_sha512(String("Bitcoin seed").to_utf8_buffer(), data);
}

Dictionary BitcoinWallet::generate_sidechain_starters(const String &master_seed_hex, const String &master_mnemonic, const Array &sidechain_slots) {
    Dictionary result;
    PackedByteArray master_seed = hex_to_bytes(master_seed_hex);

    // Generate mainchain entry
    int mainchain_slot = 999;
    PackedByteArray mainchain_seed = derive_child_key(master_seed, mainchain_slot);
    String mainchain_seed_hex = bytes_to_hex(mainchain_seed);
    String mainchain_seed_binary = bytes_to_binary(mainchain_seed);
    String mainchain_mnemonic = entropy_to_mnemonic(mainchain_seed.slice(0, 16)); // Use first 16 bytes as entropy

    Dictionary mainchain_info;
    mainchain_info["seed_hex"] = mainchain_seed_hex;
    mainchain_info["seed_binary"] = mainchain_seed_binary;
    mainchain_info["mnemonic"] = mainchain_mnemonic;
    mainchain_info["derivation_path"] = "m/44'/0'/999'";

    result["mainchain"] = mainchain_info;

    // Generate sidechain entries
    for (int i = 0; i < sidechain_slots.size(); i++) {
        int slot = sidechain_slots[i];
        PackedByteArray child_seed = derive_child_key(master_seed, slot);
        String child_seed_hex = bytes_to_hex(child_seed);
        String child_seed_binary = bytes_to_binary(child_seed);
        String child_mnemonic = entropy_to_mnemonic(child_seed.slice(0, 16)); // Use first 16 bytes as entropy

        Dictionary sidechain_info;
        sidechain_info["seed_hex"] = child_seed_hex;
        sidechain_info["seed_binary"] = child_seed_binary;
        sidechain_info["mnemonic"] = child_mnemonic;
        sidechain_info["derivation_path"] = "m/44'/0'/" + String::num_int64(slot) + "'";

        result["sidechain_" + String::num_int64(slot)] = sidechain_info;
    }
    return result;
}

BitcoinWallet::BitcoinWallet() {
}

BitcoinWallet::~BitcoinWallet() {
}

} // namespace godot