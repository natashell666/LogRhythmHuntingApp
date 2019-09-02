import pyodbc


class LogRhythmAlarmManagement:
    def __init__(self, server='localhost', port='1433', database='LogRhythmEMDB', username='LogRhythmJobMgr',
                 password='password', driver='DRIVER={ODBC Driver 13 for SQL Server}'):
        self.server = server
        self.port = port
        self.database = database
        self.username = username
        self.password = password
        self.driver = driver
        self.emdb_cnxn = None
        self.init_emdb()

    def init_emdb(self):
        if self.port == 1433:
            self.emdb_cnxn = pyodbc.connect(self.driver+';SERVER='+self.server+';DATABASE='+self.database +
                                            ';UID='+self.username+';PWD='+self.password, autocommit=True)
        else:
            self.emdb_cnxn = pyodbc.connect(self.driver+';SERVER='+self.server+','+self.port+';DATABASE=' +
                                            self.database+';UID='+self.username+';PWD='+self.password, autocommit=True)

    def close_lr_alarm(self, alarm_id, alarm_comment='Alarm closed using LogRhythm Hunting App'):
        get_alarm_query = 'SELECT * from [dbo].[Alarm] WHERE [AlarmID] = ?'
        history_insert_query = 'INSERT LogRhythm_Alarms.dbo.AlarmHistory (Comments, AlarmID, PersonID, RecordStatus, ' \
                               'DateInserted, DateUpdated, IsPrivate) VALUES(?, ?, -999, 1, ' \
                               'GETUTCDATE(), GETUTCDATE(), 0)'

        alarm_close_query = 'UPDATE [dbo].[Alarm] SET [DateUpdated] = GETUTCDATE(), [AlarmStatus] = 4, ' \
                            '[LastPersonID] = -999 WHERE [AlarmID] = ?'

        alarm_metrics_query = 'UPDATE [dbo].[AlarmMetrics] SET [ClosedOn] = GETUTCDATE(), [ModifiedBy] = -999, ' \
                              '[ModifiedOn] = GETUTCDATE() WHERE [AlarmID] = ?'

        cursor = self.emdb_cnxn.cursor()

        cursor.execute(get_alarm_query, alarm_id)
        if cursor is None or cursor.fetchone() is None:
            raise Exception('LogRhythm Alarm '+str(alarm_id)+' is invalid')

        cursor.execute(history_insert_query, alarm_comment, alarm_id)
        cursor.execute(alarm_close_query, alarm_id)
        cursor.execute(alarm_metrics_query, alarm_id)

        self.emdb_cnxn.commit()
