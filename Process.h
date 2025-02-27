#ifndef PROCESS_H
#define PROCESS_H

#include <string>

using namespace std;
/*
Basic class for Process representation
It contains relevant attributes as shown below
*/
class Process {
private:
    string pid;
    string user;
    string cmd;
    string cpu;
    string mem;
    string upTime;

public:
    Process(string pid){
        this->pid = pid;
        this->user = ProcessParser::getProcUser(this->pid);
        this->cmd = ProcessParser::getCmd(this->pid);
        this->cpu = ProcessParser::getCpuPercent(this->pid);
        this->mem = ProcessParser::getVmSize(this->pid);
        this->upTime = ProcessParser::getProcUpTime(this->pid);
    }
    void setPid(int pid);
    string getPid()const;
    string getUser()const;
    string getCmd()const;
    int getCpu()const;
    int getMem()const;
    string getUpTime()const;
    string getProcess();
};
void Process::setPid(int pid){
    this->pid = pid;
}
std::string Process::getPid()const {
    return this->pid;
}
std::string Process::getProcess(){
    
    if(!ProcessParser::isPidExisting(this->pid)){
      return "";
    }
    this->mem = ProcessParser::getVmSize(this->pid);
    this->upTime = ProcessParser::getProcUpTime(this->pid);
    this->cpu = ProcessParser::getCpuPercent(this->pid);

    return (this->pid + "   "
      + this->user
      + "   "
      + this->mem.substr(0,5)
      + "     "
      + this->cpu.substr(0,5)
      + "     "
      + this->upTime.substr(0,5)
      + "    "
      + this->cmd.substr(0,30)
      + "..."
    );
}


/* std::string Process::getUser()const {
    return this->user;
}
std::string Process::getCmd()const {
    return this->cmd;
}
int Process::getCpu()const {
    return std::stoi(this->cpu);
}
int Process::getCpu()const {
    return std::stoi(this->getMem);
} */

#endif