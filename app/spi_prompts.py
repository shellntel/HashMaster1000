"""
Semantic Password Intelligence (SPI) Prompts

This module contains focused LLM prompts for extracting passwords by semantic category.
Each prompt targets ONE specific category that requires world knowledge - things that
regex/Python cannot reliably detect.

The approach:
1. LLM extracts passwords matching the category (classification only)
2. Python validates results (confirms passwords exist in input)
3. Python counts and formats the report (no LLM needed for statistics)
"""

# Common preamble for all SPI prompts
SPI_PREAMBLE = """You are a cybersecurity analyst reviewing passwords from a corporate security assessment.
Your task is to identify passwords that match a specific semantic category.
Be thorough and precise - only include passwords you are confident belong to this category."""


def get_spi_preamble() -> str:
    """Get the SPI preamble, checking for custom override."""
    try:
        from .prompt_manager import get_prompt_manager
        manager = get_prompt_manager()
        preamble, is_custom = manager.get_prompt("preambles", "SPI_PREAMBLE")
        return preamble
    except Exception:
        return SPI_PREAMBLE


def get_spi_prompt(category_key: str, passwords: list[str]) -> str:
    """
    Generate the full SPI prompt for a category with the password list.

    Args:
        category_key: The SPI category identifier (e.g., 'sports', 'pop_culture')
        passwords: List of unique passwords to analyze

    Returns:
        Complete prompt string ready for LLM
    """
    if category_key not in SPI_CATEGORIES:
        raise ValueError(f"Unknown SPI category: {category_key}")

    category = SPI_CATEGORIES[category_key]
    password_list = "\n".join(passwords)
    count = len(passwords)

    # Use custom preamble if set
    preamble = get_spi_preamble()

    prompt = f"""{preamble}

CATEGORY: {category['name']}
{category['description']}

DATASET CONTEXT:
You are analyzing {count} unique passwords from this organization.

INCLUDE:
{category['include']}

EXCLUDE:
{category['exclude']}

EXAMPLES OF MATCHES:
{category['examples_match']}

EXAMPLES OF NON-MATCHES:
{category['examples_nomatch']}

OUTPUT RULES:
- List ONLY passwords that match this category
- One password per line, exactly as it appears in the input
- If no passwords match, output exactly: NO_MATCHES
- Do not add explanations, categories, or commentary
- Do not modify or correct the passwords{category.get('output_extra', '')}

PASSWORDS TO ANALYZE:
{password_list}

MATCHING PASSWORDS:"""

    return prompt


# SPI Category Definitions
# Each category has:
# - name: Display name
# - description: What this category captures
# - include: What TO include
# - exclude: What NOT to include
# - examples_match: Few-shot examples of matches
# - examples_nomatch: Few-shot examples of non-matches
# - output_extra: Additional output instructions (optional)

SPI_CATEGORIES = {
    "sports": {
        "name": "Sports References",
        "description": "Passwords referencing sports teams, athletes, sporting events, or sports terminology.",
        "include": """- Professional and college team names, including abbreviations (Lakers, Patriots, ManUtd, Yankees, Azcardinals, LALakers)
- Team names with location prefixes (ArizonaCardinals, LosAngelesLakers, NYYankees)
- Athlete names (Lebron, Brady, Messi, Jordan23)
- Sports terminology (touchdown, homerun, goalkeeper)
- Stadium/venue names (Fenway, Wembley)
- Championships/events (Superbowl, WorldCup, MarchMadness)
- Fan expressions with team names (Lakers4life, GoBroncos, ChiefsKingdom)""",
        "exclude": """- Generic words that happen to also be sports terms (winner, champion, goal)
- Common names that happen to match athletes unless clearly sports-related
- Numbers without sports context (23 alone is not sports, Jordan23 is)""",
        "examples_match": """goBroncos2024
Lebron#1Fan
yankees99
Touchdown!
messi10goat
ChiefsKingdom
Azcardinals24!
!Lakers4life09
DallasCowboys#1""",
        "examples_nomatch": """champion2024 (generic motivational word)
Michael23 (common name, no clear sports context)
winner! (generic word)
goalkeeper (too generic, no team/context)"""
    },

    "pop_culture": {
        "name": "Pop Culture References",
        "description": "Passwords referencing movies, TV shows, music, video games, celebrities, or entertainment.",
        "include": """- Movie/TV show titles and characters (Starwars, Batman, WalterWhite)
- Music artists, bands, song titles (Beatles, Beyonce, Bohemian)
- Video game titles and characters (Zelda, MasterChief, Minecraft)
- Celebrities (Kardashian, TaylorSwift)
- Fictional characters from books/comics (HarryPotter, Gandalf)
- Anime/manga references (Naruto, Goku, OnePiece)""",
        "exclude": """- Common first names that happen to be character names (Michael, Sarah)
- Generic words that appear in titles (love, star, dark)
- Historical figures (these go in other categories)""",
        "examples_match": """IamGroot2024
Winteriscoming!
Pokemon151
MayThe4th
NarutoUzumaki
Avengers#1""",
        "examples_nomatch": """starlight (generic word)
Dark2024 (generic adjective)
Michael123 (common name, not clearly a character reference)"""
    },

    "company": {
        "name": "Company & Organization References",
        "description": "Passwords referencing the organization name, products, internal terms, or competitor names.",
        "include": """- Company name or abbreviations (Acme, ACME2024, Microsoft, Google)
- Product or service names specific to an organization
- Internal project codenames or department names
- Competitor company names
- Industry-specific company references
- Building names or office locations (when company-specific)""",
        "exclude": """- Generic business terms (admin, corporate, office, manager)
- Generic password patterns with initials (AB.password123, XY.password001)
- Generic greeting words (Welcome, Hello, Greetings) even with numbers
- Job titles (manager, developer, director)
- Common abbreviations that aren't company-specific (SK, CG, DS, NJ, DB, TK, JR)
- Location names (these belong in Geographic category, not Company)""",
        "examples_match": """AcmeCorp2024
ProjectPhoenix!
MicrosoftRocks
GoogleEmployee
SalesforceAdmin
CompetitorSucks""",
        "examples_nomatch": """admin2024 (generic IT term)
corporate! (generic business word)
manager123 (job title, not company-specific)
Welcome@123456 (generic greeting + generic pattern)
SK.password666 (generic pattern: initials + password + number)
CG.password103 (generic pattern: initials + password + number)
LosAngeles_2028 (location, belongs in Geographic)"""
    },

    "geographic": {
        "name": "Geographic References",
        "description": "Passwords referencing cities, countries, regions, landmarks, or locations.",
        "include": """- City names, including compound forms (Chicago, London, Tokyo2024, LosAngeles, NewYork, SanFrancisco)
- City names with underscores or years (LosAngeles_2028, NYC_2024, Paris2025)
- Country names (America, Deutschland, Brasil, USA)
- State/province/region names (California, Bavaria, Ontario, Texas)
- Landmarks and monuments (Eiffel, BigBen, Statue, GoldenGate)
- Street names or addresses (MainStreet, 5thAve)
- Neighborhood names (Brooklyn, Shibuya, Manhattan)""",
        "exclude": """- Generic directional words without location context (north, east, central alone)
- Common first names that happen to be place names (Paris as a name - but LosAngeles is clearly a city)
- Very ambiguous cases (Jersey alone could be clothing)""",
        "examples_match": """NYC2024!
California$un
Tokyo#1
ParisLove
Deutschland99
LondonBridge
LosAngeles_2028
SanDiego#1""",
        "examples_nomatch": """Central123 (generic directional, no city/country)
North2024 (generic directional)
jersey99 (ambiguous, no clear location context)"""
    },

    "religious": {
        "name": "Religious & Spiritual References",
        "description": "Passwords referencing religion, faith, deities, religious texts, or spiritual concepts.",
        "include": """- Deity names (Jesus, Allah, Buddha, Shiva)
- Religious figures (Moses, Muhammad, Pope)
- Religious texts (Bible, Quran, Torah)
- Religious holidays (Christmas, Ramadan, Diwali)
- Churches/temples/mosques (Vatican, Mecca)
- Spiritual terms (blessed, faith, karma, zen)
- Religious phrases (Amen, Hallelujah, Inshallah)""",
        "exclude": """- Common names that happen to be biblical (John, Mary, David) unless clearly religious context
- Days of the week (Sunday, Saturday)
- Generic positive words (hope, peace, love)""",
        "examples_match": """Jesus2024!
Blessed&Favored
AllahAkbar
Karma123
BibleVerse316
Namaste2024""",
        "examples_nomatch": """Sunday123 (day of week, not religious context)
Hope2024 (generic positive word)
David99 (common name without religious context)"""
    },

    "family": {
        "name": "Family & Personal Relationships",
        "description": "Passwords referencing family relationships, loved ones, or personal life events.",
        "include": """- Family relationship terms (Mom, Dad, Grandma, Hubby, Wifey)
- Terms of endearment (Honey, Sweetie, Babe, Darling)
- Family-related phrases (MyKids, OurFamily, Familia)
- Anniversary/wedding references (Married2020, Anniversary)
- Baby/child references (BabyGirl, MyBoy, LittleOne)
- Pet relationship terms (FurBaby, MyDogMax)""",
        "exclude": """- Standalone names without family context (just 'Max' vs 'MyDogMax')
- Generic love words without family context (love, heart)
- Date numbers without clear family context""",
        "examples_match": """IloveMom2024
Daddy'sGirl
HubbyAndWifey
MyKids#1
Grandma99
BabyGirl2023
FurBabyLucy""",
        "examples_nomatch": """Lucy123 (just a name, no family context)
Love2024 (generic love word)
2020Wedding (ambiguous without more context)"""
    },

    "profanity": {
        "name": "Profanity & Crude Language",
        "description": "Passwords containing profanity, vulgar language, crude terms, or offensive content.",
        "include": """- Swear words and profanity (f***, s***, damn, hell)
- Sexual terms and innuendo
- Crude body part references
- Offensive slurs or derogatory terms
- Drug references (420, weed, cocaine)
- Crude humor or shock value words
- Leetspeak variations of profanity (sh1t, f4ck)""",
        "exclude": """- Mild words (darn, heck, butt)
- Medical/anatomical terms used professionally
- Words that are profanity in one language but not another (include English profanity)""",
        "examples_match": """F***You2024
Sh1tPassword
SexGod99
Drug$4Life
A$$hole123
WTF!2024""",
        "examples_nomatch": """Heck2024 (mild word)
Darn123 (mild word)
Anatomy101 (medical context)"""
    },

    "tech": {
        "name": "IT & Technology References",
        "description": "Passwords with IT/tech culture references, programming terms, or tech industry knowledge.",
        "include": """- Programming languages and terms (Python, JavaScript, sudo)
- Tech company culture (Google, Microsoft, Apple references)
- Hacker/security culture (1337, h4x0r, pwned, rootkit)
- Linux/Unix commands and references (chmod, grep, /dev/null)
- Gaming PC/hardware terms (NVIDIA, Ryzen, RGB)
- Tech memes and culture (RTFM, PEBKAC, 404NotFound)
- Cloud/DevOps terms (AWS, Docker, Kubernetes)""",
        "exclude": """- Generic computer words (computer, password, login)
- Common IT terms everyone knows (email, internet, wifi)
- Simple tech brand names used generically""",
        "examples_match": """Sudo!Root123
1337h4x0r
PythonDev2024
chmod777!
AWS@dmin
RTFM2024
KubernetesKing""",
        "examples_nomatch": """Computer123 (too generic)
Password1! (generic)
Internet99 (everyone knows this)
Apple2024 (could be fruit or company, ambiguous)"""
    },

    "language": {
        "name": "Non-English Language Detection",
        "description": "Passwords that are words or phrases from languages other than English.",
        "include": """- Complete words in other languages (Bonjour, Danke, Gracias)
- Common phrases in other languages (BuenosDias, GutenTag)
- Romanized words from non-Latin scripts (Nihongo, Shukran, Spasibo)
- Mixed language phrases (VivaLaVida, CestLaVie)
- Greetings, farewells, and common expressions""",
        "exclude": """- English words that originated from other languages but are now English (cafe, pizza, sushi)
- Brand names that happen to be foreign words
- Single letters or numbers
- Gibberish that looks foreign but isn't a real word""",
        "examples_match": """Bonjour2024 (French: Hello)
Danke123 (German: Thank you)
Gracias! (Spanish: Thank you)
CestLaVie (French: That's life)
Spasibo99 (Russian: Thank you)
Arigato! (Japanese: Thank you)""",
        "examples_nomatch": """Pizza2024 (English loanword)
Sushi99 (English loanword)
Cafe123 (English loanword)
Xyz123 (not a real word in any language)""",
        "output_extra": """
- For matches, add the detected language after a pipe: password|Language
- Example output format:
  Bonjour2024|French
  Gracias!|Spanish"""
    },

    "hobbies": {
        "name": "Hobbies & Interests",
        "description": "Passwords referencing hobbies, recreational activities, and personal interests (excluding sports and gaming).",
        "include": """- Musical instruments and music hobbies (Guitar, Drummer, Vinyl)
- Outdoor activities (Hiking, Camping, Fishing, Hunting)
- Creative hobbies (Photography, Painting, Crafting, Knitting)
- Collecting hobbies (Coins, Stamps, Antiques)
- Automotive hobbies (Mustang, Corvette, Harley, Motorcycle)
- Food/cooking hobbies (Chef, Baking, BBQKing, Foodie)
- Fitness hobbies (Yoga, CrossFit, Marathon, Gym)
- Travel and adventure (Wanderlust, Backpacker, RoadTrip)""",
        "exclude": """- Sports team/athlete references (those go in Sports)
- Video games (those go in Pop Culture)
- Professional job titles (Chef as job vs Chef as hobby)
- Generic words without hobby context""",
        "examples_match": """GuitarHero2024
Mustang67!
YogaLife
BBQKing99
Photography101
HarleyDavidson
CrossFit4Life
Wanderlust2024""",
        "examples_nomatch": """Chef123 (could be job title)
Running2024 (too generic, could be anything)
Music99 (too generic)"""
    },

    "sentiment": {
        "name": "Sentiment & Attitudes",
        "description": "Passwords expressing strong emotions, opinions, complaints, or attitudes.",
        "include": """- Work frustration (MyBossSucks, IHateMondays, QuitSoon)
- Strong opinions (ILoveX, IHateY, XRules, YSucks)
- Life attitudes (YOLO, LiveLaughLove, NoRegrets)
- Complaints and negativity (ThisJobSucks, FML, LifeIsHard)
- Rebellion/defiance (F***TheSystem, BreakRules, Rebel)
- Motivational phrases (NeverGiveUp, BelieveInYourself)
- Sarcasm and irony (SecurePassword, TotallyNotMyPassword)""",
        "exclude": """- Single emotion words without attitude context (happy, sad, angry)
- Professional/neutral phrases
- Simple positive words (good, nice, great)""",
        "examples_match": """MyBossSucks!
IHateMondays
YOLO2024
F***ThisJob
NeverGiveUp!
QuitSoon2025
ILoveMyWife
TotallyNotMyPassword""",
        "examples_nomatch": """Happy2024 (single emotion, no strong attitude)
Great123 (generic positive)
Monday99 (just a day, no sentiment)"""
    }
}


# Category display order and metadata
SPI_CATEGORY_ORDER = [
    "sports",
    "pop_culture",
    "company",
    "geographic",
    "religious",
    "family",
    "profanity",
    "tech",
    "language",
    "hobbies",
    "sentiment"
]


def get_category_display_name(category_key: str) -> str:
    """Get the display name for a category."""
    if category_key in SPI_CATEGORIES:
        return SPI_CATEGORIES[category_key]["name"]
    return category_key


def get_all_category_keys() -> list[str]:
    """Get all category keys in display order."""
    return SPI_CATEGORY_ORDER.copy()
