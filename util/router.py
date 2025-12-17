from util.response import Response

class Router:


    def __init__(self):

        self.ROUTES = []

    def add_route(self, method, path, action, exact_path=False):

        '''Store the route in self.routes'''
        self.ROUTES.append((method, path, action, exact_path))


    def route_request(self, request, handler):

        '''Look througn all of the routes'''
        for (mETHOD, pATH, aCTION, eXACT) in self.ROUTES:

            '''Make sure that the method matches'''
            if request.method == mETHOD:

                '''Look to see the value of the boolean'''
                if eXACT == True:

                    '''The path should be exactly the same'''
                    if request.path == pATH:
                        aCTION(request, handler)
                        return

                else:
                    '''Path has to start with it'''
                    if request.path.startswith(pATH):
                        aCTION(request, handler)
                        return

        '''Send a 404 not found if not found like in hello path.py'''
        rESPONCE = Response()
        rESPONCE.set_status(404, "Not Found")
        rESPONCE.text("Not Found")
        handler.request.sendall(rESPONCE.to_data())


