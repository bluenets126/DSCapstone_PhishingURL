#!/usr/bin/env python
# coding: utf-8

# In[15]:


import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, unquote
import pandas as pd
import numpy as np
import ipaddress
import re
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.firefox.options import Options
import tldextract
from difflib import SequenceMatcher

class PhishingFeatureExtractor:
    def __init__(self, url, fetch_soup=True, verbose=False):
        self.url = url
        self.domain = urlparse(url).netloc
        self.html = None
        self.soup = self._get_soup() if fetch_soup else None
        

    def _get_soup(self):
        try:
            response = requests.get(self.url, timeout=5)
            if response.status_code != 200:
                return None
            self.html = response.text  # cache HTML
            return BeautifulSoup(self.html, 'html.parser')
        except Exception as e:
            print(f"Request failed: {e}")
            return None


    def count_js_files(self):
        if not self.soup:
            return 0
        return len(self.soup.find_all('script', src=True))

    def count_css_files(self):
        if not self.soup:
            return 0
        return len(self.soup.find_all('link', rel=lambda x: x and 'stylesheet' in x.lower()))

    def count_self_ref_links(self):
        if not self.soup:
            return 0
        anchor_tags = self.soup.find_all('a', href=True)
        return sum(
            1 for tag in anchor_tags
            if urlparse(urljoin(self.url, tag['href'])).netloc == self.domain
        )

    def count_empty_ref_links(self):
        if not self.soup:
            return 0
        anchor_tags = self.soup.find_all('a')
        return sum(
            1 for tag in anchor_tags
            if not tag.has_attr('href') or not tag['href'].strip()
        )

    def count_external_ref_links(self):
        if not self.soup:
            return 0
        anchor_tags = self.soup.find_all('a', href=True)
        return sum(
            1 for tag in anchor_tags
            if urlparse(urljoin(self.url, tag['href'])).netloc != self.domain
        )

    def is_responsive(self):
        if not self.soup:
            return 0
        viewport = self.soup.find('meta', attrs={'name': 'viewport'})
        return int(bool(viewport and 'width=device-width' in viewport.get('content', '')))


    
    def count_url_redirects(self):
        try:
            response = requests.get(self.url, timeout=5, allow_redirects=True)
            return len(response.history)
        except Exception as e:
            print(f"Redirect check failed: {e}")
            return 0

    def count_self_redirects(self):
        try:
            response = requests.get(self.url, timeout=5, allow_redirects=True)
            return sum(
                1 for redirect in response.history
                if urlparse(redirect.url).netloc == self.domain
            )
        except Exception as e:
            print(f"Self-redirect check failed: {e}")
            return 0


    def count_images(self):
        if not self.soup:
            return 0
        return len(self.soup.find_all('img'))

    
    def has_copyright_info(self):
        if not self.soup:
            return 0

        text = self.soup.get_text().lower()
        patterns = [
            r"©",
            r"copyright\s+\d{4}",
            r"all rights reserved",
            r"©\s*\d{4}"
        ]
        return int(any(re.search(p, text) for p in patterns))

    
    def has_password_field(self):
        if not self.soup:
            return 0
        password_inputs = self.soup.find_all('input', {'type': 'password'})
        return int(bool(password_inputs))

    def has_hidden_fields(self):
        if not self.soup:
            return 0
        hidden_inputs = self.soup.find_all('input', {'type': 'hidden'})
        return int(bool(hidden_inputs))

    def has_submit_button(self):
        if not self.soup:
            return 0
        submit_inputs = self.soup.find_all('input', {'type': 'submit'})
        submit_buttons = self.soup.find_all('button', {'type': 'submit'})
        return int(bool(submit_inputs or submit_buttons))

    def has_external_form_submit(self):
        if not self.soup:
            return 0

        page_domain = self.domain
        for form in self.soup.find_all('form', action=True):
            action_url = form['action']
            action_domain = urlparse(action_url).netloc
            if action_domain and action_domain != page_domain:
                return 1
        return 0

    def count_iframes(self):
        if not self.soup:
            return 0
        return len(self.soup.find_all('iframe'))


    def count_popups(self):
        options = Options()
        options.add_argument("--headless")
        driver = webdriver.firefox(options=options)

        try:
            driver.get(self.url)
            return len(driver.window_handles) - 1
        except Exception as e:
            print(f"Error detecting popups for {self.url}: {e}")
            return 0
        finally:
            driver.quit()


    def count_self_redirects(self):
        try:
            response = requests.get(self.url, timeout=5, allow_redirects=True)
            original = response.url
            self_redirects = [
                r for r in response.history
                if r.headers.get('Location') == original
            ]
            return len(self_redirects)
        except requests.exceptions.RequestException as e:
            print(f"Error checking self redirects for {self.url}: {e}")
            return 0

    def has_favicon(self):
        if not self.soup:
            return 0

        icon_links = self.soup.find_all('link', rel=lambda x: x and 'icon' in x.lower())
        if icon_links:
            return 1

        # Fallback: check for /favicon.ico at root
        base_url = self.url.split('//')[0] + '//' + urlparse(self.url).netloc
        favicon_url = urljoin(base_url, '/favicon.ico')
        try:
            fav_response = requests.get(favicon_url, timeout=5)
            return int(fav_response.status_code == 200)
        except Exception as e:
            print(f"Error checking favicon file at {favicon_url}: {e}")
            return 0

    def has_title_tag(self):
        if not self.soup:
            return 0
        title = self.soup.title
        return int(bool(title and title.string and title.string.strip()))


    def count_lines_of_code(self):
        if not self.html:
            return 0
        return len(self.html.splitlines())

    def longest_line_length(self):
        if not self.html:
            return 0
        return max((len(line) for line in self.html.splitlines()), default=0)

    
    def is_https(self):
        return int(urlparse(self.url).scheme == 'https')


    def count_other_special_chars(self):
        excluded = {'?', '=', '&'}
        return sum(
            1 for char in self.url
            if not char.isalnum() and char not in excluded
        )

    def special_char_ratio(self):
        total = (self.count_equals_in_url() + self.count_questions_in_url() + self.count_ampersands_in_url() + self.count_other_special_chars())
        return total/self.calculate_url_length()

    
    def count_ampersands_in_url(self):
        return self.url.count('&')

    def count_equals_in_url(self):
        return self.url.count('=')

    def count_questions_in_url(self):
        return self.url.count('?')


    def count_digits_in_url(self):
        return sum(char.isdigit() for char in self.url)

    def digit_ratio(self):
        return self.count_digits_in_url() / self.calculate_url_length()

    def count_letters_in_url(self):
        return sum(char.isalpha() for char in self.url)

    def letter_ratio(self):
        return self.count_letters_in_url() / self.calculate_url_length()

    def count_subdomains(self):
        ext = tldextract.extract(self.url)
        subdomain = ext.subdomain
        return len(subdomain.split('.')) if subdomain else 0

    def extract_tld(self):
        result = tldextract.extract(self.url)
        return result.suffix

    def is_domain_ip(self):
        try:
            return int(bool(ipaddress.ip_address(self.domain)))
        except ValueError:
            return 0

    def extract_domain(self):
        return self.domain

    def calculate_url_length(self):
        return len(self.url)

    def calculate_domain_length(self):
        return len(self.domain)


    def has_social_net(self):
        if not self.soup:
            return 0

        social_domains = [
            "facebook.com", "twitter.com", "linkedin.com", "instagram.com",
            "youtube.com", "pinterest.com", "tiktok.com", "snapchat.com", "reddit.com"
        ]

        for link in self.soup.find_all('a', href=True):
            if any(social in link['href'] for social in social_domains):
                return 1
        return 0

    def has_obfuscation(self):
        decoded_url = unquote(self.url)
    
        if re.search(r'%[0-9a-fA-F]{2}', self.url):
            return 1

        if re.search(r'\\u[0-9a-fA-F]{4}', self.url):
            return 1

        obfuscation_chars = ['0', '1', 'l', 'O']
        if any(char in decoded_url for char in obfuscation_chars):
            return 1

        if decoded_url.count('-') > 4 or decoded_url.count('.') > 5:
            return 1

        if re.search(r'[a-zA-Z0-9]{15,}', decoded_url):
            return 1

        return 0

    def count_obfuscated_chars(self):
        decoded_url = unquote(self.url)
        count = 0

        # Count percent-encoded sequences
        count += len(re.findall(r'%[0-9a-fA-F]{2}', self.url))

        # Count Unicode escapes
        count += len(re.findall(r'\\u[0-9a-fA-F]{4}', self.url))

        # Count lookalike characters
        lookalikes = ['0', '1', 'l', 'O', 'I']
        count += sum(decoded_url.count(char) for char in lookalikes)

        # Count suspicious separators
        separators = ['-', '_', '.', '@']
        count += sum(decoded_url.count(char) for char in separators)

        return count

    def obfuscation_ratio(self):
        decoded_url = unquote(self.url)
        total_chars = len(decoded_url)
        if total_chars == 0:
            return 0.0

        # Count obfuscating characters (reuse your count_obfuscated_chars method)
        count = self.count_obfuscated_chars()

        return round(count / total_chars, 2)

    def get_title_text(self):
        if not self.soup or not self.soup.title:
            return ""
    
        title_str = self.soup.title.string
        return title_str.strip() if title_str else ""


    trusted_domains = [
        # 🏦 Finance & Payments
        "paypal.com", "bankofamerica.com", "chase.com", "citibank.com", "wellsfargo.com",
        "americanexpress.com", "capitalone.com", "discover.com", "venmo.com", "stripe.com",
        "sofi.com", "navyfederal.org", "truist.com", "usbank.com", "pnc.com",
        "squareup.com", "robinhood.com", "fidelity.com", "etrade.com", "vanguard.com",
        "ally.com", "chime.com", "zellepay.com", "mint.com", "intuit.com",
        "payoneer.com", "wise.com", "skrill.com", "revolut.com", "plaid.com",
        "bbva.com", "td.com", "hsbc.com", "scotiabank.com", "regions.com",
        "synchrony.com", "firstcitizens.com", "morganstanley.com", "americanbank.com", "nbkc.com",
        "moneygram.com", "netspend.com", "suntrust.com", "westernunion.com", "turbotax.com",
        "quicken.com", "clearnow.com", "greenlight.com", "fundera.com", "go2bank.com",

        # 🛍️ E-Commerce & Retail
        "amazon.com", "ebay.com", "walmart.com", "target.com", "bestbuy.com",
        "aliexpress.com", "etsy.com", "costco.com", "shopify.com", "wayfair.com",
        "kohls.com", "macys.com", "lowes.com", "homedepot.com", "overstock.com",
        "qvc.com", "samsclub.com", "shein.com", "nordstrom.com", "jcpenney.com",
        "chewy.com", "zappos.com", "newegg.com", "staples.com", "instacart.com",
        "doordash.com", "ubereats.com", "grubhub.com", "wish.com", "groupon.com",
        "poshmark.com", "vinted.com", "crateandbarrel.com", "revolve.com", "boohoo.com",
        "missguided.com", "modcloth.com", "anthropologie.com", "asos.com", "hm.com",
        "gap.com", "oldnavy.com", "banana.com", "uniqlo.com", "lulus.com",
        "mango.com", "sephora.com", "ulta.com", "glossier.com", "birchbox.com",

        # 🧠 Tech & Cloud
        "microsoft.com", "apple.com", "google.com", "adobe.com", "dropbox.com",
        "zoom.us", "github.com", "slack.com", "salesforce.com", "oracle.com",
        "atlassian.com", "figma.com", "canva.com", "notion.so", "airtable.com",
        "box.com", "docusign.com", "twilio.com", "cloudflare.com", "vercel.com",
        "netlify.com", "heroku.com", "aws.amazon.com", "azure.com", "gcp.com",
        "mongodb.com", "databricks.com", "snowflake.com", "newrelic.com", "splunk.com",
        "sentry.io", "segment.com", "postman.com", "algolia.com", "auth0.com",
        "okta.com", "zapier.com", "ifttt.com", "cloudera.com", "paloaltonetworks.com",
        "crowdstrike.com", "fireeye.com", "fortinet.com", "rapid7.com", "qualys.com",
        "cybereason.com", "malwarebytes.com", "bitdefender.com", "eset.com", "intuit.com",

        # 🏛️ Government & Public Services
        "irs.gov", "usa.gov", "nih.gov", "cdc.gov", "fbi.gov",
        "nsa.gov", "whitehouse.gov", "senate.gov", "house.gov", "treasury.gov",
        "ssa.gov", "va.gov", "loc.gov", "dot.gov", "usps.com",
        "uscis.gov", "cbp.gov", "ice.gov", "sec.gov", "dhs.gov",
        "state.gov", "justice.gov", "energy.gov", "epa.gov", "education.gov",
        "noaa.gov", "nps.gov", "usda.gov", "bls.gov", "census.gov",
        "labor.gov", "hhs.gov", "commerce.gov", "transportation.gov", "archives.gov",
        "gsa.gov", "usajobs.gov", "benefits.gov", "selective-service.gov", "opm.gov",
        "dol.gov", "nihlibrary.nih.gov", "law.cornell.edu", "house.texas.gov", "gov.uk",
        "canada.ca", "australia.gov.au", "india.gov.in", "gov.sg", "gov.ph",

        # 🎓 Education & Research
        "harvard.edu", "mit.edu", "stanford.edu", "yale.edu", "ox.ac.uk",
        "cam.ac.uk", "berkeley.edu", "columbia.edu", "princeton.edu", "edx.org",
        "coursera.org", "udemy.com", "khanacademy.org", "udacity.com", "pluralsight.com",
        "codecademy.com", "skillshare.com", "futurelearn.com", "open.edu", "academic.oup.com",
        "springer.com", "sciencedirect.com", "nature.com", "arxiv.org", "ieee.org",
        "researchgate.net", "jstor.org", "britannica.com", "wikipedia.org", "nptel.ac.in",
        "ocw.mit.edu", "classcentral.com", "academic.microsoft.com", "cs50.io", "colab.research.google.com",
        "quizlet.com", "quizizz.com", "gradescope.com", "canvas.com", "blackboard.com",
        "googleclassroom.com", "nsf.gov", "nasa.gov", "worldbank.org", "un.org",
        "unesco.org", "who.int", "globalcitizen.org", "ted.com", "nobelprize.org",

        # 🏥 Healthcare & Insurance
        "cvs.com", "walgreens.com", "unitedhealthgroup.com", "aetna.com", "humana.com",
        "anthem.com", "cigna.com", "kaiserpermanente.org", "mayoclinic.org", "webmd.com",
        "healthline.com", "clevelandclinic.org", "medlineplus.gov", "hopkinsmedicine.org", "mychart.com",
        "bluecross.com", "bcbs.com", "amerihealth.com", "oscarhealth.com", "zocdoc.com",
        "goodrx.com", "drugs.com", "pillpack.com", "healthcare.gov", "getcovered.org",
        "teladoc.com", "onemedical.com", "mdlive.com", "plushcare.com", "amwell.com",
        "labcorp.com", "questdiagnostics.com", "doctors.com", "heal.com", "medicalnewstoday.com",
        "everydayhealth.com", "clearmatchmedicare.com", "insure.com", "policygenius.com", "singlecare.com",
        "ems.gov", "fda.gov", "nih.gov", "cdc.gov", "hhs.gov",
        "redcross.org", "alz.org", "autismspeaks.org", "ada.org", "who.int",

        # 📺 Media & News
        "nytimes.com", "cnn.com", "bbc.com", "nbcnews.com", "foxnews.com",
        "theguardian.com", "reuters.com", "bloomberg.com", "forbes.com", "wsj.com",
        "npr.org", "huffpost.com", "cbsnews.com", "abcnews.go.com", "apnews.com",
        "politico.com", "theatlantic.com", "vox.com", "buzzfeed.com", "businessinsider.com",
        "marketwatch.com", "msnbc.com", "vice.com", "bbc.co.uk", "time.com",
        "newsweek.com", "sky.com", "economist.com", "fivethirtyeight.com", "slate.com",
        "fortune.com", "cbc.ca", "globalnews.ca", "aljazeera.com", "dw.com",
        "usatoday.com", "telegraph.co.uk", "washingtonpost.com", "rollingstone.com", "sciencemag.org",
        "newscientist.com", "wired.com", "engadget.com", "techcrunch.com", "digitaltrends.com",
        "cnet.com", "theverge.com", "tomshardware.com", "arstechnica.com", "macrumors.com"
    ]

    
    def url_similarity_index(self):
        try:
            netloc = urlparse(self.url).netloc
            ext = tldextract.extract(netloc)
            suspicious_domain = f"{ext.domain}.{ext.suffix}".lower()

            scores = [
                (trusted, SequenceMatcher(None, suspicious_domain, trusted).ratio())
                for trusted in self.trusted_domains
            ]

            if not scores:
                return 0.0

            most_similar, max_score = max(scores, key=lambda x: x[1])
            return round(max_score, 2)

        except Exception as e:
            print(f"Error processing URL similarity: {e}")
            return 0.0

    

    def extract_all(self, include_popup=False):
        features = {
            'NoOfJS': self.count_js_files(),
            'NoOfCSS': self.count_css_files(),
            'NoOfSelfRef': self.count_self_ref_links(),
            'NoOfEmptyRef': self.count_empty_ref_links(),
            'NoOfExternalRef': self.count_external_ref_links(),
            'IsResponsive': self.is_responsive(),
            'NoOfURLRedirect': self.count_url_redirects(),
            'NoOfSelfRedirect': self.count_self_redirects(),
            'NoOfImage': self.count_images(),
            'HasCopyrightInfo': self.has_copyright_info(),
            'HasPasswordField': self.has_password_field(),
            'HasHiddenFields': self.has_hidden_fields(),
            'HasSubmitButton': self.has_submit_button(),
            'HasSocialNet': self.has_social_net(),
            'HasExternalFormSubmit': self.has_external_form_submit(),
            'NoOfiFrame': self.count_iframes(),
            'HasFavicon': self.has_favicon(),
            'HasTitle': self.has_title_tag(),
            'Title': self.get_title_text(),
            'LineOfCode': self.count_lines_of_code(),
            'LargestLineLength': self.longest_line_length(),
            'IsHTTPS': self.is_https(),
            'NoOfOtherSpecialCharsInURL': self.count_other_special_chars(),
            'NoOfAmpersandInURL': self.count_ampersands_in_url(),
            'NoOfDegitsInURL': self.count_digits_in_url(),
            'NoOfLettersInURL': self.count_letters_in_url(),
            'NoOfSubDomain': self.count_subdomains(),
            'TLD': self.extract_tld(),
            'IsDomainIP': self.is_domain_ip(),
            'DomainLength': self.calculate_domain_length(),
            'URLLength': self.calculate_url_length(),
            'HasObfuscation': self.has_obfuscation(),
            'NoOfObfuscatedChar': self.count_obfuscated_chars(),
            'ObfuscationRatio': self.obfuscation_ratio(),
            'URLSimilarityIndex': self.url_similarity_index(),
            'NoOfEqualsInURL': self.count_equals_in_url(),
            'TLDLength': len(self.extract_tld()),
            'NoOfQMarkInURL': self.count_questions_in_url(),
            'LetterRatioInURL': self.letter_ratio(),
            'DegitRatioInURL': self.digit_ratio(),
            'SpacialCharRatioInURL': self.special_char_ratio(),
            'Domain': self.extract_domain()
        }
        return features

    def to_dict(self, include_popup=False):
        return self.extract_all(include_popup=include_popup)

    def to_dataframe(self, include_popup=False):
        return pd.DataFrame([self.extract_all(include_popup=include_popup)])



# In[ ]:





# In[ ]:




