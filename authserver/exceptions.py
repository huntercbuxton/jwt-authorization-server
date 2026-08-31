from werkzeug.exceptions import InternalServerError

class AppError(InternalServerError):

    def __init__(self, description, details=""):
        super().__init__(description)
        self.description = description
        self.details = details

    