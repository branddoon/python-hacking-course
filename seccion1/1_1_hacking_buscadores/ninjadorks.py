import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY_GOOGLE=os.getenv('API_KEY_GOOGLE')
SEARCH_ENGINE_ID=os.getenv('SEARCH_ENGINE_ID')

query = "Brandon Grande"
page = 1

lang = "lang_es"

url = f"https://www.googleapis.com/customsearch/v1?key={API_KEY_GOOGLE}&cx={SEARCH_ENGINE_ID}&q={query}&start={page}&lr={lang}"

data = requests.get(url).json()

results = data.get("items") 

for r in results:
    print("-------Nuevo resultaldo-------")
    print(r.get("title"));
    print(r.get("snippet"));
    print(r.get("link"));
    print("-----------------------------")