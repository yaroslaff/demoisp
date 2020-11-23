# demoisp

## Demo
[https://demoisp.herokuapp.com](https://demoisp.herokuapp.com)

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
# old: heroku ps scale:web=0
# old: heroku ps scale:web=1
heroku ps:scale web=0
heroku ps:scale web=1
heroku ps
~~~

# Other okerr resources
- [Okerr main website](https://okerr.com/)
- [Okerr-server source code repository](https://github.com/yaroslaff/okerr-dev/) 
- [Okerr client (okerrupdate) repositoty](https://github.com/yaroslaff/okerrupdate) and [okerrupdate documentation](https://okerrupdate.readthedocs.io/)
- [Okerrbench network server benchmark](https://github.com/yaroslaff/okerrbench)
- [Okerr custom status page](https://github.com/yaroslaff/okerr-status)
- [Okerr JS-powered static status page](https://github.com/yaroslaff/okerrstatusjs)
- [Okerr network sensor](https://github.com/yaroslaff/sensor)
- [Demo ISP](https://github.com/yaroslaff/demoisp) prototype client for ISP/hoster/webstudio providing paid okerr access to customers
  

