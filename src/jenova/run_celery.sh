#!/bin/sh
#celery flower -A jenova.components.tasks --broker=redis://redishost:6379/0
celery -A jenova.components.tasks worker --broker=redis://redishost:6379/0
