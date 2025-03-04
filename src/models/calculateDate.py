from datetime import datetime, timedelta

class CalculateDate:
    @staticmethod
    def approximately_equal_datetime(dt1, dt2, tolerance_seconds=40):
        diff = abs((dt1 - dt2).total_seconds())
        return diff <= tolerance_seconds