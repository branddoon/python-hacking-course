from bs4 import BeautifulSoup
import requests
import pandas as pd

def main():
    url = "https://news.ycombinator.com/"
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')

    titles = []
    links = []
    scores = []

    for item in soup.find_all('tr', class_ ='athing'):
        title_line = item.find('span', class_='titleline')
        if title_line:
            title = title_line.text
            title_link = title_line.find('a')
            link = title_link['href']
            score = item.find_next_sibling('tr').find('span', class_= 'score')
            if score:
                score = score.text
            else:
                score = 'None'
            titles.append(title)
            links.append(link)
            scores.append(score)
        else:
            print("No se encontro un titulo para los elementos, se omite")
    
    df = pd.DataFrame({
        'Title': titles,
        'Link': links,
        'Scores': scores
    })
    print(df)

    
if __name__ == "__main__":
    main()

