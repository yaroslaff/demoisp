# demoisp

## Launch
 
~~~~
python ./demoisp.py
~~~~

or
~~~~
FLASK_DEBUG=1 python ./demoisp.py
~~~~

## Heroku upload:
~~~~
git push heroku master
~~~~


If you have problem:
~~~~
xenon@braconnier:~/repo/demoisp$ git push heroku master
fatal: 'heroku' does not appear to be a git repository
fatal: Could not read from remote repository.

Please make sure you have the correct access rights
and the repository exists.
~~~~

~~~~
$ heroku git:remote -a demoisp
set git remote heroku to https://git.heroku.com/demoisp.git
~~~~

  
