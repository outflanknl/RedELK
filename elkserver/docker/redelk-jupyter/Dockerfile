#
# Part of RedELK
# Dockerfile for RedELK jupyter notebooks image
#
# Author: Outflank B.V. / Marc Smeets
#

FROM jupyter/scipy-notebook:4a112c0f11eb
LABEL maintainer="Outflank B.V. / Marc Smeets"
LABEL description="RedELK Jupyter Notebooks"

CMD start-notebook.sh --NotebookApp.token='' --NotebookApp.password='' --NotebookApp.allow_remote_access='True' --NotebookApp.allow_origin='*' --NotebookApp.base_url='/jupyter/'
