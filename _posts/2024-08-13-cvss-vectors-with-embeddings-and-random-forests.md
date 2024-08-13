---
layout: post
description: Predicting CVSS Vectors with text embeddings and random forests
comments: true
date: 2024-08-13
last-update: 22024-08-14
---

Tired of hearing/reading only about generative AI models? This post explores how Artificial Intelligence and Machine Learning can help with a very real cybersecurity problem.

## Table of Contents

- [Predicting CVSS Vectors with text embeddings and random forests](#predicting-cvss-vectors-with-text-embeddings-and-random-forests)
  - [The problem](#the-problem)
  - [What are text embeddings?](#what-are-text-embeddings)
  - [What are random forests?](#what-are-random-forests)
  - [Okay, cool, but what does all this have to do with CVEs?](#okay-cool-but-what-does-all-this-have-to-do-with-cves)
  - [The juicy part](#the-juicy-part)
    - [Step 1. Getting the data](#step-1-getting-the-data)
    - [Step 2. Getting the embeddings](#step-2-getting-the-embeddings)
    - [Step 3. Training the model](#step-3-training-the-model)
  - ['nuff test data, how do we perform on 2024 data?](#nuff-test-data-how-do-we-perform-on-2024-data)
    - [CVE-2024-39243](#cve-2024-39243)
    - [CVE-2024-27981](#cve-2024-27981)
    - [CVE-2024-4764](#cve-2024-4764)
  - [How can we improve?](#how-can-we-improve)
  - [Conclusion (written by AI!)](#conclusion-written-by-ai)

# Predicting CVSS Vectors with text embeddings and random forests

## The problem

If you work in information security, you are probably aware of the delays in enriching or classifying CVE impacts that we are experiencing in 2024.

One of the value-added by the NIST CVE analysis is the CVSS vector. In short, a CVSS vector is a concise string that summarises the characteristics and severity of a software vulnerability based on the Common Vulnerability Scoring System (CVSS). It consists of several metrics like Attack Vector, Attack Complexity, and Impact scores, each with a specific value. This vector allows for a standardised way to assess and communicate the risk associated with a vulnerability, enabling security professionals to prioritise their response efforts.

According to their website, the National Vulnerability Database (NVD) is facing a growing backlog of vulnerabilities due to increased software and changes in interagency support.

While NIST is prioritising the analysis of significant vulnerabilities, and while they are exploring long-term solutions like a consortium of stakeholders to collaborate on improving the NVD. As of today, companies involved in vulnerability management have to come up with alternative solutions to estimate the risk they are facing and prioritise vulnerability remediation.

![Image.png](https://res.craft.do/user/full/0c177b17-813d-3fbd-b831-96c793c08936/doc/3F0A08E2-24DE-4280-80C9-F59CB31DA699/3D7385E5-39CE-458A-BC4B-C097851F4CCE_2/YQ9qpWKFN1xCNYmYO0BzFZvvyMravq65UHsEL9xTO40z/Image.png)

AI is a big, hot topic today, and many think it will steal our jobs and be applied to virtually everything, in the long term.

While that sounds quite inaccurate to me, I also believe that the value of (text) embeddings is something that didn't have the right attention so far 🙂.

So, let's see how we can do something useful with AI.

## What are text embeddings?

Text embeddings are a way to represent words or phrases as dense vectors (lists of numbers) in a high-dimensional space.

In simple terms, these vectors ***capture the semantic meaning*** of the text, with respect to the training data, positioning words or phrases with similar meanings closer to each other in this space. This allows computers to perform various natural language processing tasks by measuring the distance or similarity between these vectors.

Embeddings are basically calculated as the activation of one of the latest layers of a trained neural network. Currently, the most popular way to generate an embedding model is by utilising pre-trained Large Language Models (LLMs) like BERT or GPT variants. These models have revolutionised natural language processing due to their ability to capture contextual relationships between words and generate high-quality embeddings.

It should be noted that LLMs are trained on a gargantuan amount of data to be generally useful. That means that embedding models derived from LLMs are, typically, capable of finding and encoding meaning for many domains.

As you probably know, or as you can imagine, more specialised (or fine-tuned) LLMs can perform much better in the domain they have been optimised for.

In this post, I will use a general purpose text embedding model, namely [text-embedding-gecko](https://cloud.google.com/vertex-ai/generative-ai/docs/model-reference/text-embeddings-api#model_versions) from Google VertexAI. More precisely, I will use `text-embedding-004`, which is a mono-modal embedder trained on data written in English language.

## What are random forests?

A forest is made up of trees, right? Let's start from there:

A decision tree is a flowchart-like structure used for classification or regression. It learns from data by splitting it into subsets based on feature values, creating branches and leaves. The leaf nodes represent final predictions. Training involves finding the best splits to maximize information gain (involving entropy) or, in other words, minimize impurity (i.e., number of different classes in a node).

A random forest classifies data by constructing multiple decision trees. Each tree provides a classification. The final classification is determined by a majority vote among all trees. This ensemble approach improves accuracy and robustness compared to a single decision tree.

Random forests are trained by training individual trees on a random sample (with repetition) of input data and on a random subset of features.

## Okay, cool, but what does all this have to do with CVEs?

To assign a CVSS vector to a CVE, a security analyst would carefully read and understand the vulnerability description. Then, using their security knowledge, they would create a meaningful vector, allowing the attribution of a base risk score to the vulnerability.

Can AI do that? It certainly can, to some extent.

You probably cannot just feed the description to a large language model and hope to get a super accurate CVSS vector. At least in 2024.

But fear not, AI is not just LLMs and sharks.

Getting text and embeddings is a great way to extract meaning from words. That meaning, encoded with a vector in a highly dimensional space, is a perfect candidate for classifying machine learning models.

Let's see how to combine these two things.

## The juicy part

![Image.png](https://res.craft.do/user/full/0c177b17-813d-3fbd-b831-96c793c08936/doc/3F0A08E2-24DE-4280-80C9-F59CB31DA699/FBD728AE-0348-4AC8-BEE2-7C55912D65BA_2/aASyZaZuPgl0UNqWcJXyDziphpMZdcxa7JykCKcxKfMz/Image.png)

### Step 1. Getting the data

This is the easiest part. NIST allows downloading CVE feeds straight from their site.

The data has been incrementally improving over the years, but it's still not great as historically there isn't much structure on some CVE attributes and each CNA has its own way of filing CVEs...

Anyway, NIST has been doing a decent job at assigning and improving the CVSS vector during vulnerabilities lifecycle. At least until 2024.

For our little experiment, we will download CVE data for 2022 and 2023, saving them in a handy [Google BigQuery](https://cloud.google.com/bigquery?hl=en) table.

```python
feed_format = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{}.json.gz'
years = (2022, 2023)

[...]
skipped = 0
processed = 0
for year in years:
  year_cves = []
  nvd_data = nvd_feed_url_to_json(feed_format.format(year))

  print(f"Processing data for year {year}: "
    f"{len(nvd_data['CVE_Items'])} total CVEs")
  for item in nvd_data['CVE_Items']:
    relevant_data = extract_cve_from_item(item)
    if relevant_data is None:
      skipped += 1
    else:
      year_cves.append(relevant_data)
      processed += 1

  print("Saving to bigquery")
  save_to_bigquery(
      project_id=PROJECT_ID, dataset_id=DATASET_ID, table_id=TABLE_ID,
      schema=BIGQUERY_CVES_SCHEMA, data_list=year_cves)

print(f"Processed CVEs: {processed}\nSkipped CVEs {skipped}")
```

`extract_cve_from_item` is a simple function extracting from "raw" CVE data the information we need to train our model. We only handle CVEs with `baseMetricV3` as we are only interested in CVSS v3.

```python
def extract_cve_from_item(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if 'baseMetricV3' not in item['impact']:
      return None

    en_text = next(
      (item['value'] for item in item['cve']['description']['description_data'] 
         if item['lang'] == 'en'), None)
    if en_text is None
      return None
  
    return {
        'cve_id': item['cve']['CVE_data_meta']['ID'],
        'assigner': item['cve']['CVE_data_meta']['ASSIGNER'],
        'cvssv3_vector_string': item['impact']['baseMetricV3']['cvssV3']['vectorString'],
        'cvssv3_attack_vector': item['impact']['baseMetricV3']['cvssV3']['attackVector'],
        'cvssv3_attack_complexity': item['impact']['baseMetricV3']['cvssV3']['attackComplexity'],
        'cvssv3_privileges_required': item['impact']['baseMetricV3']['cvssV3']['privilegesRequired'],
        'cvssv3_user_interaction': item['impact']['baseMetricV3']['cvssV3']['userInteraction'],
        'cvssv3_scope': item['impact']['baseMetricV3']['cvssV3']['scope'],
        'cvssv3_confidentiality_impact': item['impact']['baseMetricV3']['cvssV3']['confidentialityImpact'],
        'cvssv3_integrity_impact': item['impact']['baseMetricV3']['cvssV3']['integrityImpact'],
        'cvssv3_availability_impact': item['impact']['baseMetricV3']['cvssV3']['availabilityImpact'],
        'cvssv3_base_score': item['impact']['baseMetricV3']['cvssV3']['baseScore'],
        'cvssv3_base_severity': item['impact']['baseMetricV3']['cvssV3']['baseSeverity'],
        'english_description': en_text,
    }
```

Sample output for the above snippet:

```other
Processing data for year 2022: 24961 total CVEs
Saving to bigquery
Loaded 23746 rows to BigQuery table cves
Processing data for year 2023: 28462 total CVEs
Saving to bigquery
Loaded 25378 rows to BigQuery table cves
Processed CVEs: 70406
Skipped CVEs 5895
```

### Step 2. Getting the embeddings

Now that we have a BigQuery table with all the relevant pieces of information, we need to translate `english_description` into features we can use to classify the CVE into multiple classes.

To do so, we will be using the Google Vertex AI python API. Note that to deal with the rate limiting on that API, we are using a helper function, splitting the data into batches and making sure we don't submit more than 100 requests per second.

Here, I load the data set from BigQuery into a Pandas DataFrame:

```python
from google.cloud import bigquery
import pandas as pd

def run_bq_query(sql: str) -> pd.DataFrame:
  # Create BQ client
  bq_client = bigquery.Client(project=PROJECT_ID)
  # Try dry run before executing query to catch any errors
  job_config = bigquery.QueryJobConfig(dry_run=True, use_query_cache=False)
  # This will raise an exception if there's a query error
  bq_client.query(sql, job_config=job_config)
  # If dry run succeeds without errors, proceed to run query
  job_config = bigquery.QueryJobConfig()
  client_result = bq_client.query(sql, job_config=job_config)
  job_id = client_result.job_id
  # Wait for query/job to finish running, then get & return data frame
  df = client_result.result().to_arrow().to_pandas()
  print(f"Finished job_id: {job_id}")
  return df

cve_df = run_bq_query("SELECT * FROM nvd.cves")
```

Then I calculate the embeddings for the whole table. For the model used here, each embedding is a 768-dimensional vector.

```python
from vertexai.language_models import TextEmbeddingModel

# Initialize Vertex AI SDK
[...]
# Load the TextEmbeddingModel
model = TextEmbeddingModel.from_pretrained("text-embedding-004")

embeddings = encode_text_to_embedding_batched(
                      sentences=new_cve_df["english_description"].tolist(),
                      model=model,
                      api_calls_per_second = 95/60,
                      batch_size = 20)
```

And finally, add the new column with the embeddings to the DataFrame.

```python
cve_df.insert(
    loc=len(cve_df.columns), column='description_embeddings',
    value=embeddings.tolist())
```

### Step 3. Training the model

Now that we have numeric vectors describing our CVEs, we can try to classify them.

We could use a single classifier, trained to predict the entire CVSS Vector, but that would be inaccurate given the possible combinations of 8 different dimensions of that vector.

So, we will be training 8 different classifiers, one per each dimension of the CVSS Vector.

```python
# Dimensions we are interested in predicting
categories = [
  'cvssv3_attack_vector',
  'cvssv3_attack_complexity',
  'cvssv3_privileges_required',
  'cvssv3_user_interaction',
  'cvssv3_scope',
  'cvssv3_confidentiality_impact',
  'cvssv3_integrity_impact',
  'cvssv3_availability_impact',
]
```

For each Random Forest classifier, we will split the data into training and test sets, also calculating the accuracy:

```python
estimators = 300
X = new_cve_df['description_embeddings'].to_list()
classifiers = {}
for category in categories:
  print(f"Training random forest classifier for {category}...")
  y = new_cve_df[category].values
  # Define training and test sets
  X_train, X_test, y_train, y_test = train_test_split(
                    X, y, test_size = 0.2, random_state = 2)
  # Train the classifier
  clf = RandomForestClassifier(n_estimators=estimators,n_jobs=-1)
  clf.fit(X_train, y_train)
  classifiers[category] = {'clf': clf}
  # Calculate the classifier accuracy
  y_pred = clf.predict(X_test)
  classifiers[category]['acc'] = accuracy_score(y_test, y_pred)
```

Let's see how the classifiers performed on the test set:

```python
for k, v in classifiers.items():
  print(f"{k:30} - accuracy: {v['acc']:>6.3f}")
```

Which produced:

```plaintext
cvssv3_attack_vector           - accuracy:  0.901
cvssv3_attack_complexity       - accuracy:  0.964
cvssv3_privileges_required     - accuracy:  0.753
cvssv3_user_interaction        - accuracy:  0.924
cvssv3_scope                   - accuracy:  0.958
cvssv3_confidentiality_impact  - accuracy:  0.831
cvssv3_integrity_impact        - accuracy:  0.833
cvssv3_availability_impact     - accuracy:  0.868
```

Not bad for a quick and dirty model!

To summarise, "just" looking at the CVE description we are able to predict

- the attack vector, attack complexity, need of user interaction, scope with an accuracy of over 90%
- the impacts with an accuracy of over 83%
- the need of privileges with an accuracy of 75%

## 'nuff test data, how do we perform on 2024 data?

Just for fun, let's try out a few unclassified CVEs.

To test the classifier, I will use the following code:


```plaintext
# Test classifiers
en_desc = '<will put description here>' 

# Get the embedding of this desc and predict its category
desc_embedding = model.get_embeddings([en_desc])[0].values

# Predict each dimension of the CVSS Vector
for category in categories:
  pred = classifiers[category]['clf'].predict([desc_embedding])
  print(f"Predicted {category:>30}: {pred[0]}")
```

### CVE-2024-39243

For [this CVE](https://nvd.nist.gov/vuln/detail/CVE-2024-39243), we do have a CVSS 3.1 vector on the NIST website:

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

The CVE description recites:

```plaintext
An issue discovered in skycaiji 2.8 allows attackers to run arbitrary code
via crafted POST request to /index.php?s=/admin/develop/editor_save.
```

Let's see what our classifier predicts:

```plaintext
Predicted           cvssv3_attack_vector: NETWORK
Predicted       cvssv3_attack_complexity: LOW
Predicted     cvssv3_privileges_required: NONE
Predicted        cvssv3_user_interaction: NONE
Predicted                   cvssv3_scope: UNCHANGED
Predicted  cvssv3_confidentiality_impact: HIGH
Predicted        cvssv3_integrity_impact: HIGH
Predicted     cvssv3_availability_impact: HIGH
```

bullseye!

### CVE-2024-27981

[This CVE](https://nvd.nist.gov/vuln/detail/CVE-2024-27981) does not have a CVSS 3.1 vector on the NIST website.

The CVE description says:

```plaintext
A Command Injection vulnerability found in a Self-Hosted UniFi Network Servers
(Linux) with UniFi Network Application (Version 8.0.28 and earlier) allows a
malicious actor with UniFi Network Application Administrator credentials to
escalate privileges to root on the host device. Affected Products: UniFi
Network Application (Version 8.0.28 and earlier).
Mitigation: Update UniFi Network Application to Version 8.1.113 or later.
```

Using the same code as before, we get:

```plaintext
Predicted           cvssv3_attack_vector: NETWORK
Predicted       cvssv3_attack_complexity: LOW
Predicted     cvssv3_privileges_required: LOW
Predicted        cvssv3_user_interaction: NONE
Predicted                   cvssv3_scope: UNCHANGED
Predicted  cvssv3_confidentiality_impact: HIGH
Predicted        cvssv3_integrity_impact: HIGH
Predicted     cvssv3_availability_impact: HIGH
```

This vector roughly makes sense to me. Maybe with some caveats.

Impact dimensions seem accurate, and so does the attack vector. User interaction is not required indeed, as long as we have some (limited?) privileges: i.e., admin on the appliance.

Things that make less sense to me are:

- Scope: the description doesn't help much, as I don't know what I can do with a UniFi Network Application Administrator access.
- Attack complexity is not clear. Unless we know how to exploit this, we can't really tell...

### CVE-2024-4764

We have a vector for this one:

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

Let's see what our prediction says, just looking at the following description:

```plaintext
Multiple WebRTC threads could have claimed a newly connected audio input
leading to use-after-free. This vulnerability affects Firefox < 126.
```

```plaintext
Predicted           cvssv3_attack_vector: NETWORK
Predicted       cvssv3_attack_complexity: LOW
Predicted     cvssv3_privileges_required: NONE
Predicted        cvssv3_user_interaction: NONE
Predicted                   cvssv3_scope: UNCHANGED
Predicted  cvssv3_confidentiality_impact: HIGH
Predicted        cvssv3_integrity_impact: HIGH
Predicted     cvssv3_availability_impact: HIGH
```

Wow, another one bites the dust :)

## How can we improve?

75%, for the worst case, might not be enough in some scenarios. And, in general, we might want to improve that 83%+ too, to avoid a false sense of security (or insecurity) while calculating the overall vulnerability management risk for our domain.

There are several ways to improve the model. To name some:

1. Add more unstructured/structured data from the CVE when calculating the embeddings.
2. Add some information about the vulnerable software or intelligence data we have from different security feeds.
3. Test different classifiers or experiment with classifiers parameters.
4. Fine-tune the text embedding model for vulnerability management and cybersecurity.
5. Train a model from scratch on cybersecurity data.

## Conclusion (written by AI!)

In conclusion, this exploration into leveraging text embeddings and machine learning for CVSS vector prediction has showcased the potential of AI to address the critical challenge of timely vulnerability assessment. The ability to automatically estimate CVSS vectors based on vulnerability descriptions, even before official assignments, empowers organisations to proactively manage their security risks. While the initial results demonstrate promise, there remains room for further refinement and enhancement through the integration of domain-specific knowledge and the exploration of more advanced language models and classification algorithms.

As the cybersecurity landscape continues to evolve, the integration of AI-driven solutions like this will become increasingly vital in ensuring the resilience of our digital infrastructure.

By automating and accelerating the process of CVSS vector prediction, we can help organisations stay ahead of emerging threats and safeguard their critical assets against exploitation. The path forward involves continued research and collaboration to develop even more sophisticated models capable of accurately capturing the nuances and complexities of vulnerabilities, ultimately contributing to a more secure and resilient digital future.
