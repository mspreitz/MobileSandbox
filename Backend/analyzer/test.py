from classifier import *
from datastructure import *

sha256 = '552557183355e34353ab93e7de7fe281132cbc422eefdefcdadcb3af2235c631'

path = getPathFromSHA256(sha256)

classify('tmp/'+path+'28b7c2292d4ce54933c43a4cd309927b2c739e2a/static.json', '1223344')