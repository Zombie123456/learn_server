#!/bin/bash
celery -A demo worker -l info -Q others -n others@%h &
celery -A demo worker -Q delete_expire -n delete_expire@%h &
celery -A demo beat -l info --pidfile=
