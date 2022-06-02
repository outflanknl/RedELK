#
# Part of RedELK
# Dockerfile for RedELK jupyter notebooks image
#
# Author: Outflank B.V. / Marc Smeets
#

FROM jupyter/scipy-notebook:notebook-6.4.6
LABEL maintainer="Outflank B.V. / Marc Smeets"
LABEL description="RedELK Jupyter Notebooks"

RUN pip3 install pandas neo4j elasticsearch==7.17.3

CMD ["/bin/bash", "-o", "pipefail", "-c", "start-notebook.sh --NotebookApp.token='' --NotebookApp.password='' --NotebookApp.allow_remote_access='True' --NotebookApp.allow_origin='*' --NotebookApp.base_url='/jupyter/'"]

