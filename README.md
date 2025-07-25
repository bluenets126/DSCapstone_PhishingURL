# DSCapstone_PhishingURL
Data Science Captone Project 2 - Detecting Phishing URL's

Tableau Dashboard Link:
https://public.tableau.com/app/profile/andrew.castaldi/viz/Phishing_URL_Dashboard/Overview#1

Data was pre-calculated and saved in CSV files for training and testing purposes.  After initial exploration, a second dataset was needed and fields were manually calculated using the Phishing_Features_Class.py file.  This process was time consuming so to save time from running the notebook, I removed the data to capture the fields and saved the dataframes as csv files for use later.  I removed the cells that calculated the field, but left one in which only calculates the data for about 100 rows.  Takes a few minutes to run.

BLUF: I had to incorporate 2 datasets into one for training in order for the model to not overfit and perform better.  I used RandomForest as the model type because the dataset isn't too big.  The model was trained on only 10k records.  The model performs better than 98% in all tests performed. 

Upon initial EDA, I found that the data was looking to good to be true.  55 values that all appeared to gather its information based on the URL, with no missing data.  So I originally had the idea of creating a function to test a random URL on the model when completing.  After training a model, I tested the model on a new dataset url_dataset.csv that only had a URL and phishing label.  The model performed at 52%.  After finding this out, I had to incorporate the original dataset with the new dataset that I found.  With the new dataset taking so long to gather the info, I got 5000 rows from the new dataset, and 5000 rows from the original dataset for training.  Both datasets were split to be 1/2 phishing and 1/2 legitimate URLs, with random sampling.

After training the new model, the results seemed more realistic.  Still performed pretty well, beter than 98% in both test cases (one of 4000 records from 2nd dataset, one of 200k records from original dataset).  Made me realize how cautious you have to be with your datasets you're using for training.

I had to create a phishing feature class that captures the data, or what I believed was the data in the original class of URL's.  I was proud of this implementation and it going through this process was informative.  

The baseline Heuristic approach which just looks at the URL link and determines if it is phishing based on the URL characteristics was a good metric to see how well the model performs compared to a more simple approach.  That is compliments of CJ for his thoughts of improvement.

It seems that XGBoost or RandomForest performed almost equally as well.  Originally XGBoost was better, but after I created the new training dataset on the combined 2 datasets, RandomForest performed better.  So the final model is a RandomForest model.  

Also, I had the skeleton to implement PCA in place, but I never actually used it.  The model wasn't running slow, since the dataset was on the relative smaller side, so I decided not to use PCA in the end, but you'll see the skeleton of the PCA in the code. 

I created a function for testing at the end.  The function can take in a list of URL's or a single URL and will return the results to the users.
