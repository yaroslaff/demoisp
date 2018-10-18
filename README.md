# demoisp

## Launch
 
~~~~
python ./demoisp.py
~~~~

or
~~~~
FLASK_DEBUG=1 python ./demoisp.py
~~~~

## Heroku cheatsheet:
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

remote exec
~~~
heroku run ./demoisp.py show
~~~
or even:
~~~~
heroku run bash
~~~~

apps:
~~~~
$ heroku apps
~~~

scaling:
~~~
$ heroku ps scale:web=0
$ heroku ps scale:web=1
~~~

