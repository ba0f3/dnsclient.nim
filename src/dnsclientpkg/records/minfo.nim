type MINFORecord* = ref object of ResourceRecord
    rmailbx*: string
    emailbx*: string

method toString*(r: MINFORecord): string = r.rmailbx & " " & r.emailbx

method parse*(r: MINFORecord, data: StringStream) =
    r.rmailbx = data.getName()
    r.emailbx = data.getName()